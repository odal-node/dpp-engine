#!/usr/bin/env bash
# core-api.sh — what dpp-core offers this engine, and what the engine takes from it.
#
#   scripts/core-api.sh json     rustdoc JSON of every dpp-core crate, as the engine builds it
#   scripts/core-api.sh public   the public items of those crates, one per line
#
# Everything is read from the sources this engine is pinned to, in the cargo
# registry cache. Nothing is fetched and nothing leaves the machine: cargo runs
# `--offline`.
#
# # Why the engine's own build, and not a checkout of core
#
# `../dpp-core` is ahead of the pin, and a list made from it would describe an API
# the engine cannot call. The pin is what `Cargo.lock` resolves, and the features
# are the ones the engine's build resolves (`dpp-domain` and `dpp-rules` with
# `bundle`, without which `dpp-rules` is `no_std` and nearly empty).
#
# # Why a scratch workspace
#
# `cargo rustdoc` cannot take `--features` for a package outside the workspace,
# and the features decide the API. So the pinned sources are copied into a scratch
# workspace under `target/core-api/` and patched in for one another, which makes
# each a member that can be documented with the engine's features. The engine's
# `Cargo.lock` is copied beside them so third-party crates resolve as they do here.
#
# Needs a nightly toolchain: rustdoc's JSON output is unstable. The engine itself
# builds on the pinned stable one and never touches nightly.
#
# # What `public` lists
#
# A public item is one reachable by a path of public modules from the crate root,
# directly or through a `pub use`, glob re-exports included. It is named by the
# crate that **defines** it, so `dpp-domain` re-exporting a `dpp-rules` item lists
# it once, under `dpp-rules`. Items defined outside dpp-core (`pub use chrono::…`)
# are not core's API and are left out. Methods and associated items are not
# listed: this is the surface a `use` can name.
#
# Columns: crate, kind, name, the shortest public path, the other crates that
# export it.

set -euo pipefail

root="$(git rev-parse --show-toplevel)"
out="$root/target/core-api"
ws="$out/ws"
json="$out/json"

# `name|version|features|manifest-dir` for every dpp-core crate in the engine's build.
core_crates() {
  # `--locked` is what keeps the pin honest, and it is wrong when the local-core
  # override is active: that rewrites the lock by design (see `LOCKED` in the
  # justfile).
  local locked=(--locked)
  [[ -f "$root/.cargo/config.toml" ]] && locked=()
  local meta
  meta="$(cd "$root" && cargo metadata --format-version 1 "${locked[@]}" --offline)" || return 1
  # A dpp-core crate is a dpp-* package this workspace does not own, whether cargo
  # resolved it from the registry or from a local override.
  jq -r '
    . as $m
    | .resolve.nodes[]
    | . as $n
    | ($m.packages[] | select(.id == $n.id)) as $p
    | select($p.name | startswith("dpp-"))
    | select(($m.workspace_members | index($n.id)) == null)
    | [$p.name, $p.version, ($n.features | join(",")), ($p.manifest_path | sub("/Cargo.toml$"; ""))]
    | join("|")' <<<"$meta" | sort
}

# The crates, read once and refused when there are none. A process substitution
# that fails reads as an empty list, and an empty inventory would clear the JSON,
# write a stamp for it, and let a later run trust that stamp; so the rows are
# captured here and a failure stops the caller.
crates_or_die() {
  local rows
  rows="$(core_crates)" || {
    echo "core-api: cargo metadata could not be read" >&2
    return 1
  }
  [[ -n "$rows" ]] || {
    echo "core-api: no dpp-core crate in the engine's build" >&2
    return 1
  }
  printf '%s\n' "$rows"
}

cmd_json() {
  # The pinned sources never change under a version, so the JSON is a function of
  # the lock and of how it is built. Rebuilding it is minutes of nightly rustdoc;
  # skip that when neither has moved.
  #
  # The stamp covers the resolved crates as well as the lock: a change to a
  # manifest's features alters what is documented and leaves `Cargo.lock` as it was.
  local crates
  crates="$(crates_or_die)" || return 1
  local stamp
  stamp="$({ cat "$root/Cargo.lock"; printf '%s\n' "$crates"; declare -f cmd_json core_crates; } | sha256sum | cut -d' ' -f1)"
  # With the local-core override the sources are a working tree that changes
  # without the lock moving, so there is no stamp to trust.
  if [[ ! -f "$root/.cargo/config.toml" && -f "$json/.stamp" && "$(cat "$json/.stamp")" == "$stamp" ]]; then
    echo "core-api: the rustdoc JSON is current."
    return 0
  fi

  rm -rf "$ws" "$json"
  mkdir -p "$ws" "$json"

  # A crate resolved from the registry is a published, self-contained package:
  # it is copied into a scratch workspace and patched in for the others. One
  # resolved from a local checkout is a member of that checkout's own workspace,
  # whose manifests inherit from its root, so it is documented where it stands.
  local members=() patches=()
  while IFS="|" read -r name version _ dir; do
    if [[ "$dir" == */registry/src/* ]]; then
      cp -r "$dir" "$ws/$name"
      # Cargo resolves a workspace member's dev-dependencies even to document its
      # library, and the engine's lock holds none of core's: they are not in its
      # build, so an offline run cannot fetch them (`tracing-test`, on a runner
      # whose cache was only ever filled by the engine). Documenting a library
      # needs only what it depends on, so they go.
      awk '/^\[/ { skip = ($0 ~ /^\[.*dev-dependencies/) } !skip' "$ws/$name/Cargo.toml" >"$ws/$name/Cargo.toml.stripped"
      mv "$ws/$name/Cargo.toml.stripped" "$ws/$name/Cargo.toml"
      members+=("\"$name\"")
      patches+=("$name = { path = \"$name\" }")
    fi
  done <<<"$crates"

  if [[ ${#members[@]} -gt 0 ]]; then
    {
      echo '[workspace]'
      echo 'resolver = "2"'
      echo "members = [$(IFS=,; echo "${members[*]}")]"
      echo
      echo '[patch.crates-io]'
      printf '%s\n' "${patches[@]}"
    } >"$ws/Cargo.toml"
    cp "$root/Cargo.lock" "$ws/Cargo.lock"
  fi

  while IFS="|" read -r name version features dir; do
    echo "== $name $version features=[$features]"
    local manifest="$ws/Cargo.toml"
    [[ "$dir" != */registry/src/* ]] && manifest="$dir/../../Cargo.toml"
    local args=(--manifest-path "$manifest" -p "$name" --lib --offline)
    [[ -n "$features" ]] && args+=(--features "$features")
    CARGO_TARGET_DIR="$out/target" cargo +nightly rustdoc "${args[@]}" -- \
      -Z unstable-options --output-format json
    cp "$out/target/doc/${name//-/_}.json" "$json/$name.json"
  done <<<"$crates"
  echo "$stamp" >"$json/.stamp"
}

# One crate's public items as `definer kind name path`, tab separated.
#
# Walks the module tree from the root. A `use` is followed for its target's kind
# and defining crate; a glob `use` is expanded into the module it names, whose
# items then sit at the glob's own path.
public_of() {
  local crate="$1"
  jq -r --arg crate "${crate//-/_}" '
    def idx($c; $id): $c.index[($id | tostring)];
    def kind_of($c; $id):
      (idx($c; $id)) as $it
      | if $it != null then ($it.inner | keys[0])
        else ($c.paths[($id | tostring)].kind // "unknown") end;
    # The crate that defines the item, as rustdoc names it (underscores).
    def definer($c; $id):
      (idx($c; $id)) as $it
      | if $it != null then $crate
        else (($c.paths[($id | tostring)].crate_id // null) as $cid
              | if $cid == null then "unknown"
                else ($c.external_crates[($cid | tostring)].name // "unknown") end)
        end;
    def name_of($c; $id; $fallback):
      (idx($c; $id)) as $it
      | if $it != null then ($it.name // $fallback)
        else (($c.paths[($id | tostring)].path // [$fallback]) | last) end;

    def entries($c; $modid; $prefix; $stack):
      idx($c; $modid) as $m
      | if $m == null or ($stack | index($modid)) != null then empty
        else
          (($m.inner.module.items) // [])[] as $iid
          | idx($c; $iid) as $it
          | select($it != null)
          | ($it.inner | keys[0]) as $k
          | if $k == "module" then
              select($it.visibility == "public")
              | entries($c; $iid; $prefix + [$it.name]; $stack + [$modid])
            elif $k == "use" then
              select($it.visibility == "public")
              | $it.inner.use as $u
              | if $u.is_glob then
                  (if $u.id == null then empty
                   else entries($c; $u.id; $prefix; $stack + [$modid]) end)
                elif $u.id == null then empty
                elif kind_of($c; $u.id) == "module" then
                  # `pub use kernel::{assessability, …}` makes a private module'"'"'s
                  # children public under the name it is re-exported as.
                  entries($c; $u.id; $prefix + [$u.name]; $stack + [$modid])
                else
                  {definer: definer($c; $u.id), kind: kind_of($c; $u.id),
                   name: name_of($c; $u.id; $u.name), path: ($prefix + [$u.name]), id: $u.id}
                end
            elif $k == "impl" then empty
            else
              select($it.visibility == "public")
              | {definer: $crate, kind: $k, name: $it.name, path: ($prefix + [$it.name]), id: $iid}
            end
        end;

    # What a type or trait offers once it is named: the public inherent methods and
    # associated consts of a struct, enum or union, and the methods of a trait.
    # Trait impls add nothing here: their methods are the trait'"'"'s, listed once.
    def members($c; $e):
      (idx($c; $e.id)) as $it
      | if $it == null then empty
        elif $e.kind == "trait" then
          ($it.inner.trait.items // [])[] as $mid
          | idx($c; $mid) as $m
          | select($m != null and ($m.inner | keys[0]) == "function")
          | {definer: $e.definer, kind: "trait-method", name: ($e.name + "::" + $m.name),
             path: ($e.path + [$m.name])}
        elif ($e.kind | IN("struct", "enum", "union")) then
          ($it.inner[$e.kind].impls // [])[] as $iid
          | idx($c; $iid) as $im
          | select($im != null and $im.inner.impl.trait == null)
          | ($im.inner.impl.items // [])[] as $mid
          | idx($c; $mid) as $m
          | select($m != null and $m.visibility == "public")
          | ($m.inner | keys[0]) as $mk
          | select($mk == "function" or $mk == "assoc_const")
          | {definer: $e.definer, kind: (if $mk == "function" then "method" else "assoc-const" end),
             name: ($e.name + "::" + $m.name), path: ($e.path + [$m.name])}
        else empty end;

    . as $c
    | [entries($c; $c.root; []; [])
       | select(.definer | startswith("dpp_"))
       | select(.kind | IN("struct", "enum", "union", "trait", "trait_alias", "function",
                           "constant", "static", "type_alias", "macro", "proc_macro"))] as $items
    | ($items + [$items[] | members($c; .)])
    | .[]
    | [(.definer | gsub("_"; "-")),
       ({"function": "fn", "constant": "const", "type_alias": "type"}[.kind] // .kind),
       .name, (.path | join("::"))]
    | @tsv' "$json/$crate.json"
}

cmd_public() {
  local crates crate
  crates="$(crates_or_die)" || return 1
  while IFS="|" read -r crate _ _ _; do
    public_of "$crate" | awk -F'\t' -v via="$crate" '{print $0 "\t" via}'
  done <<<"$crates" |
    # One row per (definer, kind, name): the shortest path wins, and every other
    # crate that exports it is named.
    awk -F'\t' '
      {
        key = $1 FS $2 FS $3
        n = split($4, seg, "::")
        if (!(key in best) || n < depth[key] || (n == depth[key] && $4 < best[key])) {
          best[key] = $4; depth[key] = n
        }
        if (index("," via[key] ",", "," $5 ",") == 0) via[key] = via[key] ? via[key] "," $5 : $5
      }
      END {
        for (key in best) {
          split(key, f, FS)
          others = ""
          m = split(via[key], v, ",")
          for (i = 1; i <= m; i++) if (v[i] != f[1]) others = others ? others "," v[i] : v[i]
          print f[1] "\t" f[2] "\t" f[3] "\t" best[key] "\t" others
        }
      }' | sort -t$'\t' -k1,1 -k2,2 -k3,3
}

# The engine's Rust source, split into what ships and what only tests run.
#
# A file under `tests/`, `benches/`, `fuzz/` or `examples/`, or named for its
# tests, is test code. In any other file everything from the first
# `#[cfg(test)]` on is: the convention the OpenAPI contract test reads by too.
engine_sources() {
  # A file as code alone: a name in a comment or in a string says nothing about
  # what the engine calls. Line comments, doc comments and one-line strings go;
  # a `'"'` character literal first, since its quote would pair with a real one.
  code() {
    sed -E -e "s/'\"'//g" -e 's/"([^"\\]|\\.)*"//g' -e 's://.*$::' "$1"
  }

  local src="$out/engine"
  rm -rf "$src"
  mkdir -p "$src/prod" "$src/test"
  local rel flat
  while IFS= read -r rel; do
    flat="${rel//\//__}"
    case "$rel" in
      */tests/* | */benches/* | */fuzz/* | */examples/* | *tests.rs | *_tests.rs | *test_support*)
        code "$root/$rel" >"$src/test/$flat"
        ;;
      *)
        code "$root/$rel" | awk -v prod="$src/prod/$flat" -v test="$src/test/$flat" '
          /^[[:space:]]*#\[cfg\((all\()?test/ { cut = 1 }
          { print > (cut ? test : prod) }'
        ;;
    esac
  done < <(cd "$root" && git ls-files '*.rs' | grep -E '^(crates|cli)/')
}

# `file<TAB>identifier` and `file<TAB>A::b`, each once, for one half of the source.
tokens() {
  local half="$1"
  {
    grep -r -o -H -w -E '[A-Za-z_][A-Za-z0-9_]*' "$out/engine/$half" | sort -u |
      awk -F: '{ n = split($1, p, "/"); print p[n] "\t" $2 }'
    # `A::b` splits on its two colons into A, an empty field and b.
    grep -r -o -H -E '[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*' "$out/engine/$half" | sort -u |
      awk -F: '{ n = split($1, p, "/"); print p[n] "\t" $2 "::" $4 }'
    # A method call, as `.name`: the receiver's type is not in the text.
    grep -r -o -H -E '\.[A-Za-z_][A-Za-z0-9_]*\(' "$out/engine/$half" | sort -u |
      awk -F: '{ n = split($1, p, "/"); t = $2; sub(/\($/, "", t); print p[n] "\t" t }'
  } | LC_ALL=C sort -s -t$'\t' -k1,1
}

# `tier crate kind name path evidence-files` for every public item.
#
#   used        named in shipped code, in a file that also names the crate that
#               defines or exports it (or the engine's glue crates), or as
#               `Type::name` outright
#   called      a method called by a name no other core method and no engine fn
#               has, in a file that names core, on a value whose type is inferred
#   maybe       the name is there and nothing says it is core's: a method called
#               on something the file also names the type of, or a name that
#               another crate or the engine defines too
#   tests-only  only test code names it
#   unused      nothing does
#
# This is a name match, not name resolution, and says so: `used` can be a
# collision on a name core and the engine share, and `unused` is right unless a
# macro or a glob import hides the name.
cmd_unused() {
  local public="$out/public.tsv"
  cmd_public >"$public"
  engine_sources
  tokens prod >"$out/tokens.prod"
  tokens test >"$out/tokens.test"
  grep -r -h -o -E '\bfn +[A-Za-z_][A-Za-z0-9_]*' "$out/engine/prod" | awk '{ print $2 }' | sort -u >"$out/engine.fns"

  awk -F'\t' -v OFS='\t' -v prod="$out/tokens.prod" -v test="$out/tokens.test" -v fns="$out/engine.fns" '
    function crate_ident(c) { gsub("-", "_", c); return c }

    # Score one half: for every core row, in how many files is it named?
    function score(file, half,    i, bare, ty, mk, ms, j, nm) {
      for (i = 1; i <= nrows; i++) {
        bare = rbare[i]; ty = rtype[i]
        if (ty != "") {
          if ((ty "::" bare) in seen) { strong[half, i]++; continue }
          if ((ty in seen) && (bare in seen)) { weak[half, i]++; continue }
          # Called on a value whose type the file never names. Only a file that
          # names core at all can be calling a core method, and only a name no
          # other core method and no engine fn shares says which one it is.
          if (("." bare) in seen) {
            mk = 0
            nm = split(rmarks[i], ms, ",")
            for (j = 1; j <= nm; j++) if (ms[j] in seen) mk = 1
            if (mk && mcount[bare] == 1 && !(bare in edef)) called[half, i]++
            else if (mk) weak[half, i]++
          }
          continue
        }
        if (!(bare in seen)) continue
        mk = 0
        nm = split(rmarks[i], ms, ",")
        for (j = 1; j <= nm; j++) if (ms[j] in seen) mk = 1
        if (mk && !rambiguous[i]) strong[half, i]++; else weak[half, i]++
      }
    }

    function flush(half) {
      if (curfile != "") score(curfile, half)
      delete seen; curfile = ""
    }

    function read_tokens(path, half,    line, f) {
      curfile = ""
      while ((getline line < path) > 0) {
        split(line, f, "\t")
        if (f[1] != curfile) { flush(half); curfile = f[1] }
        seen[f[2]] = 1
      }
      flush(half)
      close(path)
    }

    FILENAME == ARGV[1] {
      n = ++nrows
      rcrate[n] = $1; rkind[n] = $2; rname[n] = $3; rpath[n] = $4
      m = split($3, parts, "::")
      rbare[n] = parts[m]
      rtype[n] = (m > 1) ? parts[1] : ""
      marks = crate_ident($1)
      k = split($5, ex, ",")
      for (i = 1; i <= k; i++) if (ex[i] != "") marks = marks "," crate_ident(ex[i])
      rmarks[n] = marks ",dpp_types,dpp_common"
      if (rtype[n] == "") count[rbare[n]]++; else mcount[rbare[n]]++
      next
    }

    END {
      while ((getline fn < fns) > 0) edef[fn] = 1
      for (i = 1; i <= nrows; i++) rambiguous[i] = (rtype[i] == "" && count[rbare[i]] > 1)
      read_tokens(prod, "p")
      read_tokens(test, "t")
      for (i = 1; i <= nrows; i++) {
        if (strong["p", i] > 0) tier = "used"
        else if (called["p", i] > 0) tier = "called"
        else if (weak["p", i] > 0) tier = "maybe"
        else if (strong["t", i] + called["t", i] + weak["t", i] > 0) tier = "tests-only"
        else tier = "unused"
        print tier, rcrate[i], rkind[i], rname[i], rpath[i], strong["p", i] + called["p", i] + weak["p", i]
      }
    }' "$public" /dev/null | sort -t$'\t' -k1,1 -k2,2 -k3,3 -k4,4
}

# The shape of every struct and enum, and every literal const, in the files on stdin:
# `kind name file:line members`, tab separated. A member is `name`, or `name=wire`
# when a serde rename gives it another one on the wire. Const members are the value.
#
# Read from source, not from rustdoc: rustdoc drops serde attributes, and the wire
# name is the one a client sees. It leans on rustfmt, which every file here has
# been through, for one member per line; a type it cannot read is not reported.
shapes() {
  xargs awk -v OFS='\t' '
    FNR == 1 { cut = 0; intype = 0; await = 0; rename = "" }
    cut { next }
    /^[[:space:]]*#\[cfg\((all\()?test/ { cut = 1; next }
    {
      line = $0
      sub(/^[[:space:]]*\/\/.*$/, "", line)
      sub(/[[:space:]]\/\/[^"]*$/, "", line)
    }

    # A literal const, one line.
    !intype && match(line, /^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?const[[:space:]]+[A-Z][A-Z0-9_]*[[:space:]]*:[^=]*=[[:space:]]*.*;[[:space:]]*$/) {
      decl = line
      sub(/^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?const[[:space:]]+/, "", decl)
      cname = decl; sub(/[[:space:]]*:.*$/, "", cname)
      cval = decl; sub(/^[^=]*=[[:space:]]*/, "", cval); sub(/[[:space:]]*;[[:space:]]*$/, "", cval)
      if (cval ~ /^"([^"\\]|\\.)*"$/ || cval ~ /^-?[0-9][0-9_.]*[a-z0-9]*$/) print "const", cname, FILENAME ":" FNR, cval
      next
    }

    # The head of a braced struct or enum.
    !intype && match(line, /^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?(struct|enum)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/) {
      head = substr(line, RSTART, RLENGTH)
      n = split(head, w, /[[:space:]]+/)
      kind = w[n - 1]; tname = w[n]; tloc = FILENAME ":" FNR
      members = ""; depth = 0; rename = ""
      if (line ~ /\{/) { intype = 1; started = 1 }
      # A tuple or unit struct holds no named member, and its name is still one core
      # may own: it is recorded with none.
      else if (line ~ /\(/ || line ~ /;[[:space:]]*$/) { print kind, tname, tloc, ""; next }
      else { await = 1; next }
    }
    await {
      if (line ~ /\{/) { intype = 1; await = 0; started = 1 }
      else if (line ~ /;[[:space:]]*$/) { await = 0; next }
      else next
    }

    intype {
      if (!started && depth == 1) {
        if (line ~ /^[[:space:]]*#\[/) {
          if (match(line, /rename[[:space:]]*=[[:space:]]*"[^"]*"/)) {
            r = substr(line, RSTART, RLENGTH); sub(/^[^"]*"/, "", r); sub(/"$/, "", r); rename = r
          }
        } else if (kind == "struct" && match(line, /^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?[A-Za-z_][A-Za-z0-9_#]*:([^:]|$)/)) {
          m = substr(line, RSTART, RLENGTH); sub(/^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?/, "", m); sub(/:.*$/, "", m)
          sub(/^r#/, "", m)
          members = members (members == "" ? "" : ",") m (rename != "" ? "=" rename : ""); rename = ""
        } else if (kind == "enum" && match(line, /^[[:space:]]*[A-Z][A-Za-z0-9_]*([[:space:]]*[,({=]|[[:space:]]*$)/)) {
          m = substr(line, RSTART, RLENGTH); sub(/^[[:space:]]*/, "", m); sub(/[^A-Za-z0-9_].*$/, "", m)
          members = members (members == "" ? "" : ",") m (rename != "" ? "=" rename : ""); rename = ""
        }
      }
      started = 0
      o = gsub(/\{/, "{", line); c = gsub(/\}/, "}", line)
      depth += o - c
      if (depth <= 0) {
        print kind, tname, tloc, members
        intype = 0
      }
    }'
}

# `relation score kind engine-type engine-location core-crate core-type shared engine-only core-only`
#
# A shadow is an engine type that restates a core one. Two shapes of it are read:
#
#   same-name    the type has the name of a core type, whatever it holds
#   same-shape   most of what it holds is in core, member for member
#
# and two for constants: `same-value` for a literal core already names, and
# `same-name-other-value` for a core name carrying another value, which is a
# drift waiting to be read. Members match by name with case and underscores
# ignored, so `product_group_data` and `productGroupData` are one, and by wire
# name where serde renames one.
#
# The matching, from three files, so the self-test can feed it what it likes:
# the public list, core's shapes (`crate kind name location members`) and the
# engine's (`kind name location members`).
join_shadows() {
  local public="$1" coref="$2" engine="$3"
  awk -F'\t' -v OFS='\t' -v public="$public" -v coref="$coref" '
    function norm(s) { s = tolower(s); gsub(/_/, "", s); return s }
    function keys(m,    a, b) {
      # `name` or `name=wire` -> the normalised names it goes by, `|` apart.
      split(m, a, "=")
      return (a[2] == "") ? norm(a[1]) : norm(a[1]) "|" norm(a[2])
    }
    BEGIN {
      while ((getline line < public) > 0) { split(line, p, "\t"); ispublic[p[1] SUBSEP p[2] SUBSEP p[3]] = 1 }
      while ((getline line < coref) > 0) {
        split(line, f, "\t")
        crate = f[1]; kind = f[2]; name = f[3]
        if (!((crate, kind, name) in ispublic)) continue
        if (kind == "const") {
          cv[++nc] = f[5]; cn[nc] = name; ck[nc] = crate
          byvalue[f[5]] = byvalue[f[5]] " " nc
          bycname[norm(name)] = bycname[norm(name)] " " nc
          continue
        }
        id = ++nt
        tcrate[id] = crate; tkind[id] = kind; tname[id] = name; tmembers[id] = f[5]
        bytname[kind SUBSEP norm(name)] = bytname[kind SUBSEP norm(name)] " " id
        byany[norm(name)] = byany[norm(name)] " " id
        m = split(f[5], ms, ",")
        tcount[id] = m
        for (i = 1; i <= m; i++) {
          mk = keys(ms[i]); k = split(mk, kk, "|")
          for (j = 1; j <= k; j++) { tm[id, kk[j]] = 1; index_of[kind SUBSEP kk[j]] = index_of[kind SUBSEP kk[j]] " " id }
        }
      }
    }
    {
      kind = $1; name = $2; loc = $3; mem = $4
      if (kind == "const") {
        # The name comes first, whatever the value: a short one says nothing of itself,
        # but a name core owns carrying another value is the drift this looks for.
        nn = split(bycname[norm(name)], ns, " ")
        for (i = 1; i <= nn; i++) {
          if (cv[ns[i]] != $4) print "same-name-other-value", 1, "const", name, loc, ck[ns[i]], cn[ns[i]], "engine " $4, "", "core " cv[ns[i]]
          else print "same-value", 1, "const", name, loc, ck[ns[i]], cn[ns[i]], $4, "", ""
        }
        # By value alone, a short one is too common to mean anything.
        if (length($4) >= 6) {
          nv = split(byvalue[$4], vs, " ")
          for (i = 1; i <= nv; i++) if (norm(cn[vs[i]]) != norm(name)) print "same-value", 1, "const", name, loc, ck[vs[i]], cn[vs[i]], $4, "", ""
        }
        next
      }
      # Named for a core type of another kind: a struct here, an enum there.
      nk = split(byany[norm(name)], oks, " ")
      for (q = 1; q <= nk; q++) if (tkind[oks[q]] != kind) print "same-name-other-kind", 0, kind, name, loc, tcrate[oks[q]], tname[oks[q]] " (" tkind[oks[q]] ")", 0, "", ""
      m = split(mem, ms, ",")
      delete cand
      for (i = 1; i <= m; i++) {
        mk = keys(ms[i]); k = split(mk, kk, "|")
        delete seenid
        for (j = 1; j <= k; j++) {
          nn = split(index_of[kind SUBSEP kk[j]], ids, " ")
          for (q = 1; q <= nn; q++) if (!(ids[q] in seenid)) { seenid[ids[q]] = 1; cand[ids[q]]++ }
        }
      }
      # Named for a core type, whatever it holds.
      nn = split(bytname[kind SUBSEP norm(name)], ids, " ")
      for (q = 1; q <= nn; q++) if (!(ids[q] in cand)) cand[ids[q]] = 0
      for (id in cand) {
        shared = cand[id]; ecount = m; ccount = tcount[id]
        union = ecount + ccount - shared; jac = (union > 0) ? shared / union : 0
        samename = ((kind SUBSEP norm(name)) in bytname) && index(" " bytname[kind SUBSEP norm(name)] " ", " " id " ")
        minshared = (kind == "enum") ? 2 : 3
        rel = ""
        if (samename) rel = "same-name"
        # What is on each side only.
        eo = ""; co = ""
        for (i = 1; i <= m; i++) { mk = keys(ms[i]); k = split(mk, kk, "|"); hit = 0; for (j = 1; j <= k; j++) if ((id, kk[j]) in tm) hit = 1; if (!hit) { split(ms[i], a, "="); eo = eo (eo == "" ? "" : ",") a[1] } }
        cm = split(tmembers[id], cms, ",")
        for (i = 1; i <= cm; i++) { mk = keys(cms[i]); k = split(mk, kk, "|"); hit = 0; for (j = 1; j <= k; j++) { for (q2 = 1; q2 <= m; q2++) { ek = keys(ms[q2]); ke = split(ek, ee, "|"); for (z = 1; z <= ke; z++) if (ee[z] == kk[j]) hit = 1 } } if (!hit) { split(cms[i], a, "="); co = co (co == "" ? "" : ",") a[1] } }
        # A type of two members has little to be a shape of, so it counts only when
        # it is the other side exactly: every member on each side matched, and nothing
        # else. Two members answering to one core member (an alias) leave the other
        # core member unmatched, and that is not a copy.
        if ((jac >= 0.75 && shared >= minshared) || (jac == 1 && shared >= 2 && eo == "" && co == "")) rel = (rel == "" ? "same-shape" : rel "+same-shape")
        if (rel == "") continue
        printf "%s\t%.2f\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", rel, jac, kind, name, loc, tcrate[id], tname[id], shared, eo, co
      }
    }' "$engine" | sort -t$'\t' -k1,1 -k2,2nr -k4,4
}

# The engine's shipped Rust files, absolute, one per line: no test file, and the
# readers below stop at the first `#[cfg(test)]` of the rest.
engine_prod_files() {
  (cd "$root" && git ls-files '*.rs' | grep -E '^(crates|cli)/' |
    grep -Ev '/tests/|/benches/|/fuzz/|/examples/|tests\.rs$|_tests\.rs$|test_support' |
    sed "s|^|$root/|")
}

cmd_shadows() {
  cmd_public >"$out/public.tsv"
  local engine_files="$out/engine.files"
  engine_prod_files >"$engine_files"
  # Locations relative to the repository, so a report reads the same anywhere.
  shapes <"$engine_files" | sed "s|$root/||" >"$out/shapes.engine"

  : >"$out/shapes.core"
  local crates name dir
  crates="$(crates_or_die)" || return 1
  while IFS="|" read -r name _ _ dir; do
    find "$dir/src" -name '*.rs' ! -name '*tests.rs' ! -name '*_test.rs' |
      shapes | awk -F'\t' -v OFS='\t' -v crate="$name" '{ print crate, $0 }' >>"$out/shapes.core"
  done <<<"$crates"

  join_shadows "$out/public.tsv" "$out/shapes.core" "$out/shapes.engine"
}

# The words a core enum puts on a wire, for the files on stdin:
# `type variant file:line word via`, tab separated. `via` says where the word was
# read: `serde` for a derived Serialize or Deserialize (the enum's `rename_all`
# and a variant's `rename` applied, as serde does), `arm` for a match arm that
# returns a literal (`Self::Draft => "draft"`), which is how the enums that write
# their own wire form spell it.
#
# Read from source, not from rustdoc, for the reason `shapes` is. An enum that
# converts through `from`/`into`, or is untagged, has no variant words on the wire
# and is left to its arms.
wire_words() {
  xargs awk -v OFS='\t' '
    function snake(v, sep,    out, i, ch) {
      out = ""
      for (i = 1; i <= length(v); i++) {
        ch = substr(v, i, 1)
        if (i > 1 && ch ~ /[A-Z]/) out = out sep
        out = out ch
      }
      return out
    }
    function wire(v, rule) {
      if (rule == "lowercase") return tolower(v)
      if (rule == "UPPERCASE") return toupper(v)
      if (rule == "camelCase") return tolower(substr(v, 1, 1)) substr(v, 2)
      if (rule == "snake_case") return tolower(snake(v, "_"))
      if (rule == "SCREAMING_SNAKE_CASE") return toupper(snake(v, "_"))
      if (rule == "kebab-case") return tolower(snake(v, "-"))
      if (rule == "SCREAMING-KEBAB-CASE") return toupper(snake(v, "-"))
      return v
    }
    function brackets(s,    t, o, c) { t = s; o = gsub(/\[/, "", t); t = s; c = gsub(/\]/, "", t); return o - c }

    FNR == 1 { cut = 0; attrs = ""; ab = 0; inenum = 0; await = 0; inimpl = 0; iname = "" }
    cut { next }
    /^[[:space:]]*#\[cfg\((all\()?test/ { cut = 1; next }
    {
      line = $0
      sub(/^[[:space:]]*\/\/.*$/, "", line)
      sub(/[[:space:]]\/\/[^"]*$/, "", line)
    }
    line ~ /^[[:space:]]*$/ { next }

    # The attributes in front of an item, which may run over several lines.
    !inenum && !inimpl && !await && ab > 0 { attrs = attrs " " line; ab += brackets(line); next }
    !inenum && !inimpl && !await && line ~ /^[[:space:]]*#\[/ { attrs = attrs " " line; ab = brackets(line); next }

    # The head of an enum.
    !inenum && !inimpl && !await && match(line, /^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?enum[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/) {
      head = substr(line, RSTART, RLENGTH)
      n = split(head, w, /[[:space:]]+/)
      ename = w[n]
      ser = (attrs ~ /Serialize|Deserialize/) && attrs !~ /(from|into|try_from)[[:space:]]*=/ && attrs !~ /untagged/
      erule = ""
      if (match(attrs, /rename_all[[:space:]]*=[[:space:]]*"[^"]*"/)) {
        erule = substr(attrs, RSTART, RLENGTH); sub(/^[^"]*"/, "", erule); sub(/"$/, "", erule)
      }
      attrs = ""; nv = 0; depth = 0; vr = ""; vskip = 0; started = 0
      if (line ~ /\{/) { inenum = 1; started = 1 } else { await = 1; next }
    }
    await {
      if (line ~ /\{/) { inenum = 1; await = 0; started = 1 } else next
    }

    inenum {
      if (!started && depth == 1) {
        if (line ~ /^[[:space:]]*#\[/) {
          if (match(line, /rename[[:space:]]*=[[:space:]]*"[^"]*"/)) {
            r = substr(line, RSTART, RLENGTH); sub(/^[^"]*"/, "", r); sub(/"$/, "", r); vr = r
          }
          if (line ~ /serde\([^)]*skip/) vskip = 1
        } else if (match(line, /^[[:space:]]*[A-Z][A-Za-z0-9_]*([[:space:]]*[,({=]|[[:space:]]*$)/)) {
          m = substr(line, RSTART, RLENGTH); sub(/^[[:space:]]*/, "", m); sub(/[^A-Za-z0-9_].*$/, "", m)
          if (!vskip) { nv++; vname[nv] = m; vwire[nv] = (vr != "") ? vr : wire(m, erule); vloc[nv] = FILENAME ":" FNR }
          vr = ""; vskip = 0
        }
      }
      started = 0
      o = gsub(/\{/, "{", line); c = gsub(/\}/, "}", line)
      depth += o - c
      if (depth <= 0) {
        if (ser) for (i = 1; i <= nv; i++) print ename, vname[i], vloc[i], vwire[i], "serde"
        inenum = 0
      }
      next
    }

    # A match arm that answers with a literal: `Self::Draft => "draft"`, `A | B =>
    # "x"`, `Self::A => f.write_str("a")`. `Self` is the type of the impl it is in;
    # a named one is read wherever it stands.
    (p = index(line, "=>")) > 0 {
      rhs = substr(line, p + 2); sub(/^[[:space:]]+/, "", rhs)
      if (match(rhs, /^(f\.write_str\()?"([^"\\]|\\.)*"/)) {
        lit = substr(rhs, RSTART, RLENGTH); sub(/^[^"]*"/, "", lit); sub(/"$/, "", lit)
        na = split(substr(line, 1, p - 1), alts, /\|/)
        for (i = 1; i <= na; i++) if (match(alts[i], /(Self|[A-Z][A-Za-z0-9_]*)::[A-Z][A-Za-z0-9_]*/)) {
          t = substr(alts[i], RSTART, RLENGTH)
          split(t, tv, "::")
          ty = (tv[1] == "Self") ? iname : tv[1]
          if (ty != "") print ty, tv[2], FILENAME ":" FNR, lit, "arm"
        }
      }
    }

    # The head of an impl: the type is what follows `for`, or what follows `impl`.
    !inimpl && match(line, /^[[:space:]]*(unsafe[[:space:]]+)?impl([[:space:]]|<)/) {
      h = line; sub(/\{.*$/, "", h); sub(/[[:space:]]+where[[:space:]].*$/, "", h)
      sub(/^[[:space:]]*(unsafe[[:space:]]+)?impl/, "", h)
      if (h ~ /[[:space:]]for[[:space:]]/) sub(/^.*[[:space:]]for[[:space:]]+/, "", h)
      else sub(/^<[^>]*>/, "", h)
      sub(/^[[:space:]]+/, "", h)
      sub(/^[A-Za-z_][A-Za-z0-9_]*::/, "", h)
      iname = match(h, /^[A-Z][A-Za-z0-9_]*/) ? substr(h, RSTART, RLENGTH) : ""
      attrs = ""; inimpl = 1; idepth = 0; iopen = 0
    }
    inimpl {
      o = gsub(/\{/, "{", line); c = gsub(/\}/, "}", line)
      idepth += o - c
      if (o > 0) iopen = 1
      if (iopen && idepth <= 0) { inimpl = 0; iname = "" }
      next
    }
    { attrs = "" }'
}

# Every string literal in the files on stdin, outside comments and attributes:
# `file:line content before after`, tab separated, where `before` and `after` are
# the sixteen and fourteen characters of the line either side of it, which is how
# a report tells a match pattern from a JSON key. A literal that runs over lines
# is one, newline and all.
# Raw strings, byte strings and character literals are read, so a quote inside a
# `'"'` does not open a string. It reads rustfmt-ed source, as `shapes` does.
literals() {
  xargs awk -v OFS='\t' '
    function brackets(s,    t, o, c) { t = s; o = gsub(/\[/, "", t); t = s; c = gsub(/\]/, "", t); return o - c }
    FNR == 1 { cut = 0; instr = 0; incom = 0; ab = 0 }
    cut { next }
    /^[[:space:]]*#\[cfg\((all\()?test/ { cut = 1; next }
    !instr && !incom && ab > 0 { ab += brackets($0); next }
    !instr && !incom && /^[[:space:]]*#!?\[/ { ab = brackets($0); next }
    {
      line = $0
      if (!instr && !incom && index(line, "\"") == 0 && index(line, "/*") == 0) next
      n = length(line); i = 1
      while (i <= n) {
        ch = substr(line, i, 1)
        if (incom) {
          if (ch == "*" && substr(line, i + 1, 1) == "/") { incom = 0; i += 2 } else i++
          continue
        }
        if (instr) {
          if (rawh < 0 && ch == "\\") { buf = buf substr(line, i, 2); i += 2; continue }
          if (ch == "\"" && (rawh < 0 || substr(line, i + 1, rawh) == hs)) {
            instr = 0; i += 1 + (rawh > 0 ? rawh : 0)
            if (buf != "") print loc, buf, pre, substr(line, i, 14)
            continue
          }
          buf = buf ch; i++; continue
        }
        if (ch == "/" && substr(line, i + 1, 1) == "/") break
        if (ch == "/" && substr(line, i + 1, 1) == "*") { incom = 1; i += 2; continue }
        if (ch == "\"") { instr = 1; rawh = -1; hs = ""; buf = ""; loc = FILENAME ":" FNR; pre = substr(line, (i > 16 ? i - 16 : 1), (i > 16 ? 16 : i - 1)); i++; continue }
        if (ch == "r" && (i == 1 || substr(line, i - 1, 1) !~ /[A-Za-z0-9_]/)) {
          j = i + 1; hs = ""
          while (substr(line, j, 1) == "#") { hs = hs "#"; j++ }
          if (substr(line, j, 1) == "\"") { instr = 1; rawh = length(hs); buf = ""; loc = FILENAME ":" FNR; pre = substr(line, (i > 16 ? i - 16 : 1), (i > 16 ? 16 : i - 1)); i = j + 1; continue }
        }
        if (ch == "\047") {
          if (substr(line, i + 2, 1) == "\047") { i += 3; continue }
          if (substr(line, i + 1, 1) == "\\") {
            j = index(substr(line, i + 3), "\047")
            if (j > 0 && j < 12) { i += 3 + j; continue }
          }
        }
        i++
      }
      if (instr && rawh < 0 && substr(line, n, 1) != "\\") buf = buf "\n"
      else if (instr && rawh >= 0) buf = buf "\n"
    }'
}

# `file:line word candidates` for each engine literal that is a word a public core
# enum puts on a wire. Candidates are `crate::Type::Variant`, space apart: a word
# like `other` is a variant of many enums, and says less for it.
join_literals() {
  local public="$1" words="$2" lits="$3"
  awk -F'\t' -v OFS='\t' -v public="$public" -v words="$words" '
    BEGIN {
      while ((getline line < public) > 0) { split(line, p, "\t"); ispublic[p[1], p[2], p[3]] = 1 }
      while ((getline line < words) > 0) {
        split(line, f, "\t")
        if (!((f[1], "enum", f[2]) in ispublic)) continue
        id = f[1] "::" f[2] "::" f[3]
        if (index(" " cand[f[5]] " ", " " id " ") == 0) cand[f[5]] = cand[f[5]] " " id
      }
    }
    ($2 in cand) { print $1, $2, substr(cand[$2], 2), $3, $4 }' "$lits"
}

# The literals the engine writes that a core enum already names, ranked by how
# likely each is a copy of the vocabulary and not a coincidence of words.
#
#   A   the file holds two or more different words of one enum: it is retyping
#       the enum
#   B   one word of an enum, and the word is not an everyday one (it has a hyphen,
#       an underscore, a capital or a digit, or is eight letters or more)
#   C   one everyday word: `draft`, `other`, `none`
#
# Written to `$out/literals.report` as `tier place file:line word candidate n`,
# where `candidate` is the enum the file writes most words of and `n` how many
# enums the word is a variant of. `cmd_literals` prints it; the gate reads
# clusters from it (`literal_clusters`).
literal_report() {
  cmd_public >"$out/public.tsv"
  engine_prod_files >"$out/engine.files"
  literals <"$out/engine.files" | sed "s|^$root/||" >"$out/literals.engine"

  # Read before the loop: a process substitution that fails reads as an empty
  # list, and no core crate would then be a core crate with no word to find.
  local crates name dir
  crates="$(crates_or_die)" || return 1
  : >"$out/words.core"
  while IFS="|" read -r name _ _ dir; do
    find "$dir/src" -name '*.rs' ! -name '*tests.rs' ! -name '*_test.rs' |
      wire_words | awk -F'\t' -v OFS='\t' -v crate="$name" '{ print crate, $0 }' >>"$out/words.core"
  done <<<"$crates"
  # The order of a word's candidates breaks a tie between two enums that a file
  # writes as many words of, so it must not depend on the locale.
  LC_ALL=C sort -u -o "$out/words.core" "$out/words.core"

  join_literals "$out/public.tsv" "$out/words.core" "$out/literals.engine" >"$out/literal.hits"
  awk -F'\t' -v OFS='\t' '
    function everyday(w) { return !(w ~ /[-_A-Z0-9]/ || length(w) >= 8) }
    # Where the literal stands, from the line around it.
    function place(pre, post) {
      if (post ~ /^[[:space:]]*(=>|\|)/) return "pattern"
      if (pre ~ /=>[[:space:]]*$/) return "arm-value"
      if (pre ~ /(==|!=)[[:space:]]*$/ || post ~ /^[[:space:]]*(==|!=)/) return "compare"
      if (post ~ /^[[:space:]]*:([^:]|$)/) return "key"
      if (pre ~ /\[[[:space:]]*$/ || (pre ~ /^[[:space:]]*$/ && post ~ /^[[:space:]]*,/) || (pre ~ /,[[:space:]]*$/ && post ~ /^[[:space:]]*[],]/)) return "list"
      if (pre ~ /:[[:space:]]*$/) return "value"
      return "other"
    }
    NR == FNR {
      split($1, l, ":"); file = l[1]
      n = split($3, cs, " ")
      for (i = 1; i <= n; i++) { split(cs[i], p, "::"); k = file SUBSEP p[1] "::" p[2]; if (!((k, $2) in seen)) { seen[k, $2] = 1; distinct[k]++ } }
      next
    }
    {
      split($1, l, ":"); file = l[1]
      n = split($3, cs, " "); best = 0; bestc = ""
      for (i = 1; i <= n; i++) { split(cs[i], p, "::"); k = file SUBSEP p[1] "::" p[2]; if (distinct[k] > best) { best = distinct[k]; bestc = cs[i] } }
      tier = (best >= 2) ? "A" : (everyday($2) ? "C" : "B")
      print tier, place($4, $5), $1, $2, bestc, n
    }' "$out/literal.hits" "$out/literal.hits" | sort -t$'\t' -k1,1 -k2,2 -k3,3 >"$out/literals.report"
}

cmd_literals() {
  literal_report || return 1
  cat "$out/literals.report"
}

# A file that writes two or more different words of one core enum, at least one of
# them where the file decides on it (a match pattern, a comparison, an element of a
# list, the value of an arm), is writing that enum out again. One finding for the
# file and the enum, in the form `join_shadows` reports a shadow in, so one record
# in `core-shadows.tsv` holds it: `same-words<TAB>file<TAB>crate::Enum<TAB>reason`.
#
# One word is not a finding. `draft` or `ok` in a file is as likely a word the
# engine owns, and a JSON key or a value on its own says too little of what the
# file does with it. Those stay in the report.
literal_clusters() {
  awk -F'\t' -v OFS='\t' '
    {
      split($3, l, ":"); e = $5; sub(/::[^:]*$/, "", e); k = l[1] SUBSEP e
      if (!(k in first) || l[2] + 0 < firstline[k]) { first[k] = $3; firstline[k] = l[2] + 0 }
      hits[k]++
      if (!((k, $4) in seen)) { seen[k, $4] = 1; words[k] = words[k] (words[k] == "" ? "" : ",") $4; distinct[k]++ }
      if ($2 ~ /^(pattern|list|compare|arm-value)$/) strong[k] = 1
    }
    END {
      for (k in hits) if (strong[k] && distinct[k] >= 2) {
        split(k, a, SUBSEP); split(a[2], p, "::")
        print "same-words", 1, "literals", a[1], first[k], p[1], p[2], distinct[k], words[k], ""
      }
    }' "$1" | sort -t$'\t' -k4,4 -k6,6 -k7,7
}

cmd_literal_findings() {
  literal_report || return 1
  literal_clusters "$out/literals.report"
}

# The findings against the shadows recorded as accepted, each with its reason.
#
# Fails for a shadow nobody has recorded, for a record of one that is no longer
# found (so an entry cannot outlive the thing it excuses, and the list only
# shrinks as shadows are fixed), and for a record with no reason. A record is
# `relation<TAB>engine-type<TAB>core-crate::core-type<TAB>reason`.
compare_shadows() {
  local found="$1" allow="$2"
  awk -F'\t' -v allow="$allow" '
    BEGIN {
      while ((getline line < allow) > 0) {
        if (line ~ /^[[:space:]]*(#|$)/) continue
        split(line, f, "\t")
        key = f[1] "\t" f[2] "\t" f[3]
        listed[key] = 1
        if (f[4] == "") {
          printf "NO REASON: %s -> %s (%s) is recorded without one\n", f[2], f[3], f[1] > "/dev/stderr"
          bad = 1
        }
      }
    }
    {
      key = $1 "\t" $4 "\t" $6 "::" $7
      seen[key] = 1
      if (!(key in listed)) {
        if ($1 == "same-words") printf "NEW: %s writes %d words of %s::%s as strings (first at %s) [%s]\n     words: %s\n", $4, $8, $6, $7, $5, $1, $9 > "/dev/stderr"
        else printf "NEW: %s %s (%s) restates %s::%s [%s]\n     only here: %s | only in core: %s\n", $3, $4, $5, $6, $7, $1, $9, $10 > "/dev/stderr"
        bad = 1
      }
    }
    END {
      for (key in listed) if (!(key in seen)) {
        split(key, k, "\t")
        printf "STALE: %s -> %s (%s) is recorded and no longer found: delete the line\n", k[2], k[3], k[1] > "/dev/stderr"
        bad = 1
      }
      exit bad
    }' "$found"
}

# The gate: regenerate the findings and hold them to the record.
cmd_check() {
  local allow="${CORE_API_ALLOW:-$root/scripts/core-shadows.tsv}"
  cmd_json
  cmd_shadows >"$out/shadows.tsv"
  cmd_literal_findings >>"$out/shadows.tsv"
  if compare_shadows "$out/shadows.tsv" "$allow"; then
    echo "core-shadows: $(wc -l <"$out/shadows.tsv") finding(s), every one recorded in scripts/core-shadows.tsv."
  else
    cat >&2 <<'MSG'

core-shadows: the engine declares something dpp-core already has.

Use the core item. Where it cannot be used as it is, the fix is in core: derive
the trait the wire needs, or expose the part the engine wants, and consume that.
A file that writes two or more of one core enum's words as strings takes them
from the enum: its `ALL`, its wire form, or serde, whichever core offers.
Only when the engine type is deliberate (an adapter, a request body that holds
less than core's type, a name core happens to share for another thing), record it
in scripts/core-shadows.tsv with the reason. Delete a STALE line the same way.
MSG
    return 1
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    json) cmd_json ;;
    public) cmd_public ;;
    unused) cmd_unused ;;
    shadows) cmd_shadows ;;
    literals) cmd_literals ;;
    check) cmd_check ;;
    *)
      echo "usage: $0 json|public|unused|shadows|literals|check" >&2
      exit 2
      ;;
  esac
fi
