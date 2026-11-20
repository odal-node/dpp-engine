#!/usr/bin/env bash
# analyze_handler_errors.sh — Find handler error branches no test exercises.
#
# For every handler, extract the error codes it can return (using CODE_TOKENS from
# openapi_contract.rs), then search the test code to see if any test exercises
# those error paths.
#
# Usage: bash scripts/analyze_handler_errors.sh
# Output: Markdown report of untested error branches.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATES_DIR="$PROJECT_ROOT/crates"

# CODE_TOKENS from openapi_contract.rs — error tokens and their HTTP codes
# Format: "token|code"
CODE_TOKENS=(
    "not_found_error(|404"
    "conflict_error(|409"
    "refused_chain_error(|409"
    "validation_error(|422"
    "require_write(|403"
    "require_admin(|403"
    "RequireWrite|403"
    "RequireAdmin|403"
    "parse_passport_id(|400"
    "http_problem::not_found(|404"
    "http_problem::bad_request(|400"
    "http_problem::unprocessable(|422"
    "StatusCode::BAD_REQUEST|400"
    "StatusCode::FORBIDDEN|403"
    "StatusCode::NOT_FOUND|404"
    "StatusCode::NOT_ACCEPTABLE|406"
    "StatusCode::CONFLICT|409"
    "StatusCode::GONE|410"
    "StatusCode::UNPROCESSABLE_ENTITY|422"
    "StatusCode::NOT_IMPLEMENTED|501"
    "StatusCode::BAD_GATEWAY|502"
    "StatusCode::SERVICE_UNAVAILABLE|503"
)

# Map error codes to status tokens used in tests
declare -A CODE_TO_STATUS_TOKEN
CODE_TO_STATUS_TOKEN[400]="StatusCode::BAD_REQUEST"
CODE_TO_STATUS_TOKEN[403]="StatusCode::FORBIDDEN"
CODE_TO_STATUS_TOKEN[404]="StatusCode::NOT_FOUND"
CODE_TO_STATUS_TOKEN[406]="StatusCode::NOT_ACCEPTABLE"
CODE_TO_STATUS_TOKEN[409]="StatusCode::CONFLICT"
CODE_TO_STATUS_TOKEN[410]="StatusCode::GONE"
CODE_TO_STATUS_TOKEN[422]="StatusCode::UNPROCESSABLE_ENTITY"
CODE_TO_STATUS_TOKEN[501]="StatusCode::NOT_IMPLEMENTED"
CODE_TO_STATUS_TOKEN[502]="StatusCode::BAD_GATEWAY"
CODE_TO_STATUS_TOKEN[503]="StatusCode::SERVICE_UNAVAILABLE"

# Exclude infrastructure files
HANDLER_EXCLUDES="mod.rs error.rs health.rs node_health.rs"

# Collect all test content into a temp file
TEST_CONTENT=$(mktemp)
trap 'rm -f "$TEST_CONTENT" "$RESULTS_FILE"' EXIT

RESULTS_FILE=$(mktemp)

# Gather all test file content
for crate_dir in "$CRATES_DIR"/*/; do
    tests_dir="${crate_dir%/}/tests"
    if [ -d "$tests_dir" ]; then
        find "$tests_dir" -name '*.rs' -type f -exec cat {} + >> "$TEST_CONTENT" 2>/dev/null || true
    fi
done

# Parse router.rs files to build handler -> routes mapping.
# Uses Perl to handle multi-line .route() calls correctly with paren-depth tracking.
# Output format: handler_name|path  (one per line)
declare -A HANDLER_ROUTES

for crate_dir in "$CRATES_DIR"/*/; do
    router_file="$crate_dir/src/router.rs"
    [ -f "$router_file" ] || continue

    while IFS='|' read -r handler_name path; do
        [ -z "$handler_name" ] && continue
        if [ -n "${HANDLER_ROUTES[$handler_name]+x}" ]; then
            HANDLER_ROUTES[$handler_name]="${HANDLER_ROUTES[$handler_name]},$path"
        else
            HANDLER_ROUTES[$handler_name]="$path"
        fi
    done < <(perl -0777 -ne '
        # Strip test modules
        s/#\[cfg\(test\)\].*?\n\}//gs;
        # Find each .route("PATH" and use paren depth to find the block
        while ( /\.route\(\s*"([^"]+)"\s*,?\s*/g ) {
            my $path = $1;
            my $pos = pos($_);
            my $depth = 1;
            my $block = "";
            while ($depth > 0 && $pos < length($_)) {
                my $ch = substr($_, $pos, 1);
                if ($ch eq "(") { $depth++; }
                elsif ($ch eq ")") { $depth--; last if $depth == 0; }
                $block .= $ch;
                $pos++;
            }
            # Extract handler names from method calls
            while ($block =~ /\b(get|post|put|delete|patch)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*(?:::[a-zA-Z_][a-zA-Z0-9_]*)?)\s*\)/g) {
                my $h = $2;
                $h =~ s/.*:://;  # strip module prefix
                print "$h|$path\n";
            }
        }
    ' "$router_file" 2>/dev/null || true)
done

# Find handler files and analyze
total_untested=0
total_handlers=0

for crate_dir in "$CRATES_DIR"/*/; do
    crate_dir="${crate_dir%/}"
    handlers_dir="$crate_dir/src/handlers"
    [ -d "$handlers_dir" ] || continue
    
    for handler_file in "$handlers_dir"/*.rs; do
        [ -f "$handler_file" ] || continue
        filename=$(basename "$handler_file")
        
        # Skip excluded files
        skip=0
        for excl in $HANDLER_EXCLUDES; do
            if [ "$filename" = "$excl" ]; then
                skip=1
                break
            fi
        done
        [ "$skip" -eq 1 ] && continue
        
        rel_path="${handler_file#$PROJECT_ROOT/}"
        content=$(cat "$handler_file")
        
        # Extract handler function names — only `pub async fn` because that is
        # the visibility boundary a router reaches across modules. Internal helpers
        # are private `async fn` and are not route handlers.
        handler_names=$(echo "$content" | \
            grep -oP 'pub\s+async\s+fn\s+\K\w+(?=\s*\()' 2>/dev/null || true)
        
        [ -z "$handler_names" ] && continue
        
        # Extract per-handler error codes by scanning each handler's body,
        # not the entire file. Uses Perl to extract the body of each pub async fn.
        # Output: handler_name|code  (one per line)
        unset HANDLER_CODES
        declare -A HANDLER_CODES
        while IFS='|' read -r h_name h_code; do
            [ -z "$h_name" ] && continue
            if [ -n "${HANDLER_CODES[$h_name]+x}" ]; then
                HANDLER_CODES[$h_name]="${HANDLER_CODES[$h_name]} $h_code"
            else
                HANDLER_CODES[$h_name]="$h_code"
            fi
        done < <(perl -e '
            use strict;
            my $content = do { local $/; <STDIN> };
            # Strip test modules
            $content =~ s/#\[cfg\(test\)\].*?\n\}//gs;
            
            my @tokens = (
                ["not_found_error(", 404], ["conflict_error(", 409], ["refused_chain_error(", 409],
                ["validation_error(", 422], ["require_write(", 403], ["require_admin(", 403],
                ["RequireWrite", 403], ["RequireAdmin", 403], ["parse_passport_id(", 400],
                ["http_problem::not_found(", 404], ["http_problem::bad_request(", 400],
                ["http_problem::unprocessable(", 422], ["StatusCode::BAD_REQUEST", 400],
                ["StatusCode::FORBIDDEN", 403], ["StatusCode::NOT_FOUND", 404],
                ["StatusCode::NOT_ACCEPTABLE", 406], ["StatusCode::CONFLICT", 409],
                ["StatusCode::GONE", 410], ["StatusCode::UNPROCESSABLE_ENTITY", 422],
                ["StatusCode::NOT_IMPLEMENTED", 501], ["StatusCode::BAD_GATEWAY", 502],
                ["StatusCode::SERVICE_UNAVAILABLE", 503],
            );
            my @skip_codes = (401, 500);
            
            # Find each pub async fn and extract its body.
            # Cannot use [^)]* for params because State(state) contains ) inside.
            # Use paren-depth tracking for both params and body.
            while ($content =~ /pub\s+async\s+fn\s+(\w+)\s*\(/g) {
                my $name = $1;
                my $pos = pos($content);
                # Skip past the params with paren-depth tracking
                my $pdepth = 1;
                while ($pdepth > 0 && $pos < length($content)) {
                    my $ch = substr($content, $pos, 1);
                    if ($ch eq "(") { $pdepth++; }
                    elsif ($ch eq ")") { $pdepth--; }
                    $pos++;
                }
                # Skip optional return type and whitespace until {
                # Return type may contain < > with nested generics, skip to {
                while ($pos < length($content) && substr($content, $pos, 1) ne "{") {
                    $pos++;
                }
                # Now extract the body with brace-depth tracking
                $pos++; # skip the opening {
                my $depth = 1;
                my $body = "";
                while ($depth > 0 && $pos < length($content)) {
                    my $ch = substr($content, $pos, 1);
                    if ($ch eq "{") { $depth++; }
                    elsif ($ch eq "}") { $depth--; last if $depth == 0; }
                    $body .= $ch;
                    $pos++;
                }
                # Check which tokens appear in this body
                for my $t (@tokens) {
                    my ($token, $code) = @$t;
                    next if grep { $_ == $code } @skip_codes;
                    if ($body =~ /\Q$token\E/) {
                        print "$name|$code\n";
                    }
                }
            }
        ' < "$handler_file" 2>/dev/null || true)
        
        # Check each handler + code combination.
        # Test coverage is checked per-test-function: a handler+code is "tested" only
        # if some test function body contains both a reference to the handler's route
        # and an assertion of that status code. Checking the entire test corpus for
        # both strings produces false positives ("import" is everywhere).
        for handler_name in $handler_names; do
            routes="${HANDLER_ROUTES[$handler_name]:-}"
            handler_codes="${HANDLER_CODES[$handler_name]:-}"
            [ -z "$handler_codes" ] && continue
            
            for code in $handler_codes; do
                tested=0
                status_token="${CODE_TO_STATUS_TOKEN[$code]:-}"
                
                if [ -n "$routes" ] && [ -n "$status_token" ]; then
                    # Use Perl to split test content into individual test functions,
                    # then check if any single test contains both the route path
                    # (with {param} normalized) and the status token.
                    IFS=',' read -ra route_array <<< "$routes"
                    for route in "${route_array[@]}"; do
                        # Normalize route: replace {param} with [^/]+ for regex matching
                        normalized=$(echo "$route" | sed 's/{[^}]*}/[^\/]*/g')
                        result=$(perl -e '
                            use strict;
                            my $route_re = $ARGV[0];
                            my $status = $ARGV[1];
                            my $test_file = $ARGV[2];
                            
                            # Read all test files
                            my $content = "";
                            open(my $fh, "<", $test_file) or exit 0;
                            local $/; $content = <$fh>; close($fh);
                            
                            # Split into test functions (fn name { ... })
                            # Look for #[test] or async fn ... { blocks
                            while ($content =~ /(?:#\[(test|ignore)\].*?\n)?(?:pub\s+)?async\s+fn\s+\w+\s*\([^)]*\)\s*(?:->\s*\S+\s*)?\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/gs) {
                                my $test_body = $2;
                                my $route_re = qr/$route_re/;
                                if ($test_body =~ $route_re && $test_body =~ /\Q$status\E/) {
                                    print "yes\n";
                                    exit 0;
                                }
                            }
                            # Also check sync test functions
                            while ($content =~ /(?:#\[(test|ignore)\].*?\n)?fn\s+(\w+)\s*\([^)]*\)\s*(?:->\s*\S+\s*)?\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/gs) {
                                my $name = $2;
                                my $test_body = $3;
                                next if $name !~ /test|check|verify/;
                                my $route_re = qr/$route_re/;
                                if ($test_body =~ $route_re && $test_body =~ /\Q$status\E/) {
                                    print "yes\n";
                                    exit 0;
                                }
                            }
                            print "no\n";
                        ' "$normalized" "$status_token" "$TEST_CONTENT" 2>/dev/null || echo "no")
                        if [ "$result" = "yes" ]; then
                            tested=1
                            break
                        fi
                    done
                elif [ -z "$routes" ] && [ -n "$status_token" ]; then
                    # No route found — check if handler name + status appear in same test
                    result=$(perl -e '
                        use strict;
                        my $handler = $ARGV[0];
                        my $status = $ARGV[1];
                        my $test_file = $ARGV[2];
                        
                        open(my $fh, "<", $test_file) or exit 0;
                        local $/; my $content = <$fh>; close($fh);
                        
                        while ($content =~ /(?:#\[(test|ignore)\].*?\n)?(?:pub\s+)?async\s+fn\s+\w+\s*\([^)]*\)\s*(?:->\s*\S+\s*)?\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/gs) {
                            my $test_body = $2;
                            if ($test_body =~ /\Q$handler\E && $test_body =~ /\Q$status\E/) {
                                print "yes\n";
                                exit 0;
                            }
                        }
                        print "no\n";
                    ' "$handler_name" "$status_token" "$TEST_CONTENT" 2>/dev/null || echo "no")
                    [ "$result" = "yes" ] && tested=1
                fi
                
                if [ "$tested" -eq 0 ]; then
                    route_str="${routes:-no route found}"
                    echo "$rel_path|$handler_name|$code|$route_str" >> "$RESULTS_FILE"
                    total_untested=$((total_untested + 1))
                fi
            done
        done
    done
done

# Generate report
if [ "$total_untested" -eq 0 ]; then
    echo "No untested error branches found."
    exit 0
fi

# Count unique handlers
total_handlers=$(cut -d'|' -f1,2 "$RESULTS_FILE" | sort -u | wc -l)

echo "# Untested Handler Error Branches"
echo ""
echo "Total: $total_untested untested error branches across $total_handlers handlers"
echo ""

# Group by handler
cut -d'|' -f1,2 "$RESULTS_FILE" | sort -u | while IFS='|' read -r file handler; do
    codes=$(grep "^${file}|${handler}|" "$RESULTS_FILE" | cut -d'|' -f3 | sort -un | tr '\n' ',' | sed 's/,$//')
    routes=$(grep "^${file}|${handler}|" "$RESULTS_FILE" | head -1 | cut -d'|' -f4)
    echo "## \`$file\`"
    echo "- **${handler}()** — routes: \`$routes\`"
    echo "  Untested codes: [$codes]"
    echo ""
done

# Summary by code
echo "## Summary by error code"
echo ""
cut -d'|' -f3 "$RESULTS_FILE" | sort -n | uniq -c | sort -rn | while read count code; do
    echo "- \`$code\`: $count handler(s)"
done

# Summary by crate
echo ""
echo "## Summary by crate"
echo ""
cut -d'|' -f1 "$RESULTS_FILE" | cut -d'/' -f2 | sort | uniq -c | sort -rn | while read count crate; do
    echo "- \`$crate\`: $count handler(s)"
done
