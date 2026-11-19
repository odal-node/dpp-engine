#!/usr/bin/env bash
# Record CI time per job and decide when to partition the test suite.
#
# # Partitioning trigger
#
# When the longest test job has a median above 10 minutes on a warm cache,
# partition that job across runners:
#
#   - One job builds the test binaries once:
#       cargo nextest archive --features integration-tests --archive-file nextest.tar.zst
#     and uploads the archive as an artifact.
#
#   - N jobs each run:
#       cargo nextest run --archive-file nextest.tar.zst \
#         --workspace-remap . --partition hash:k/N
#     where k ranges from 0 to N-1, each with its own Postgres service.
#
# A warm cache is assumed when the `dpp-node` image job uses the GHA cache
# (scope `dpp-node`) — the runner reports a cache hit in the build log.
# Until the median exceeds 10 minutes on a warm cache, splitting the tests
# would mostly split compile time, not test time.
#
# # What was considered and not adopted
#
# - sccache in CI: it draws on the same 10 GiB Actions cache, and it caches
#   neither incremental builds, nor proc-macros, nor binaries.
# - Cache storage above 10 GiB: the free tier limit; paid tiers add cost per
#   organisation without guaranteeing the time savings sccache cannot provide.
# - Larger runners: double the price for a proportional speedup; the trigger
#   above is cheaper and defers the cost until it is needed.
# - Retrying failed tests by default: here, a test that fails one time in a
#   hundred is a finding — silencing it hides the signal.
#
# # Why local-only
#
# Requires an authenticated `gh` CLI with read access to workflow runs.
# CI cannot use `gh` to read its own runs — the data is available only
# through the GitHub API with a token that has the `workflow` scope, which
# the default GITHUB_TOKEN does not grant for the runs API.
#
# Usage: bash scripts/ci-timing.sh [N]
#   N  Number of recent successful ci.yml runs to analyse (default: 12)
set -euo pipefail

N="${1:-12}"

# Fetch the last N successful ci.yml runs.
# `gh run list` returns JSON; we filter for success and take the newest first.
runs="$(gh run list --workflow=ci.yml --json databaseId,createdAt,updatedAt,conclusion \
  --limit "$((N * 3))" \
  | jq -r '[.[] | select(.conclusion == "success")] | .[:'"$N"'] | .[] | "\(.databaseId) \(.createdAt) \(.updatedAt)"')"

if [ -z "$runs" ]; then
  echo "ci-timing: no successful ci.yml runs found" >&2
  exit 1
fi

# Collect per-job timing data.
# Format per line: <job_name> <duration_seconds>
declare -A job_times

while IFS= read -r run_line; do
  run_id="${run_line%% *}"
  run_created="${run_line#* }"
  run_created="${run_created%% *}"
  run_updated="${run_line##* }"

  # Compute wall-clock for the whole run.
  created_epoch=$(date -d "$run_created" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$run_created" +%s 2>/dev/null)
  updated_epoch=$(date -d "$run_updated" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$run_updated" +%s 2>/dev/null)
  wall_clock=$((updated_epoch - created_epoch))

  echo "Run ${run_id}: $((wall_clock / 60))m $((wall_clock % 60))s wall-clock"

  # Fetch jobs for this run. `--json jobs` is required to reach nested job fields;
  # `--json name,startedAt,completedAt` applies to the run, not the jobs.
  # Tab-separated because job names contain spaces.
  jobs="$(gh run view "$run_id" --json jobs --jq '.jobs[] | "\(.name)\t\(.startedAt)\t\(.completedAt)"')"

  while IFS=$'\t' read -r job_name job_started job_completed; do
    [ -z "$job_name" ] && continue

    started_epoch=$(date -d "$job_started" +%s)
    completed_epoch=$(date -d "$job_completed" +%s)
    duration=$((completed_epoch - started_epoch))

    # Append to the job's time list.
    job_times["$job_name"]="${job_times["$job_name"]:-} $duration"
  done <<< "$jobs"
done <<< "$runs"

# Print per-job summary: median and max in minutes.
echo ""
echo "Job medians and maximums (minutes):"
echo "---"
printf "%-45s %8s %8s\n" "Job" "Median" "Max"
echo "---"

# Sort keys into an array to iterate in order. Associative array keys with spaces
# cannot be split by word splitting, so we use a newline-delimited sort.
mapfile -t sorted_keys < <(printf '%s\n' "${!job_times[@]}" | sort)

for job_name in "${sorted_keys[@]}"; do
  times="${job_times[$job_name]}"
  # Sort times numerically.
  sorted=$(echo "$times" | tr ' ' '\n' | grep -v '^$' | sort -n)
  count=$(echo "$sorted" | wc -l)
  count=$((count + 0))  # trim whitespace

  if [ "$count" -eq 0 ]; then
    continue
  fi

  # Median: middle value for odd count, average of two middle for even.
  mid=$((count / 2))
  if [ $((count % 2)) -eq 1 ]; then
    median_val=$(echo "$sorted" | sed -n "$((mid + 1))p")
  else
    val1=$(echo "$sorted" | sed -n "${mid}p")
    val2=$(echo "$sorted" | sed -n "$((mid + 1))p")
    median_val=$(( (val1 + val2) / 2 ))
  fi

  # Max: last value in sorted list.
  max_val=$(echo "$sorted" | tail -1)

  # Convert to minutes with one decimal.
  median_min=$(awk "BEGIN {printf \"%.1f\", $median_val / 60}")
  max_min=$(awk "BEGIN {printf \"%.1f\", $max_val / 60}")

  printf "%-45s %7sm %7sm\n" "$job_name" "$median_min" "$max_min"
done

echo "---"
echo ""
echo "Trigger: partition the test suite when the longest test job median exceeds 10.0m on a warm cache."
