#!/usr/bin/env bash
# Run Ligero and Aurora Google Benchmark binaries (same build tree).
# Usage:
#   ./run_snark_benchmarks.sh
#   BUILD_DIR=/path/to/build OUT_DIR=./results BENCHMARK_REPETITIONS=100 ./run_snark_benchmarks.sh
#   ./run_snark_benchmarks.sh --benchmark_filter='BM_LIGERO_.*CANTOR.*'
# Extra args after a lone "--" are passed to BOTH binaries:
#   ./run_snark_benchmarks.sh -- --benchmark_filter='.*CANTOR_BASIS.*'
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/build}"
LIGERO_BIN="${LIGERO_BIN:-${BUILD_DIR}/libiop/benchmark_ligero}"
AURORA_BIN="${AURORA_BIN:-${BUILD_DIR}/libiop/benchmark_aurora}"

BENCHMARK_REPETITIONS="${BENCHMARK_REPETITIONS:-100}"
OUT_DIR="${OUT_DIR:-}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

EXTRA=()
PASSTHROUGH=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --)
      shift
      PASSTHROUGH=("$@")
      break
      ;;
    *)
      EXTRA+=("$1")
      shift
      ;;
  esac
done

if [[ -z "${OUT_DIR}" ]]; then
  OUT_DIR="${REPO_ROOT}/benchmark_results/${STAMP}"
fi
mkdir -p "${OUT_DIR}"

for b in "${LIGERO_BIN}" "${AURORA_BIN}"; do
  if [[ ! -x "${b}" ]]; then
    echo "error: missing or not executable: ${b}" >&2
    echo "  Build first: cmake -S ${REPO_ROOT} -B ${BUILD_DIR} && cmake --build ${BUILD_DIR} --target benchmark_ligero benchmark_aurora" >&2
    exit 1
  fi
done

COMMON=(
  --benchmark_repetitions="${BENCHMARK_REPETITIONS}"
  --benchmark_out_format=json
)

echo "repo:       ${REPO_ROOT}"
echo "build:      ${BUILD_DIR}"
echo "output dir: ${OUT_DIR}"
echo "repetitions: ${BENCHMARK_REPETITIONS}"
echo

run_one() {
  local name="$1"
  local bin="$2"
  local json_out="${OUT_DIR}/${name}.json"
  echo "=== ${name} ==="
  "${bin}" "${COMMON[@]}" --benchmark_out="${json_out}" "${EXTRA[@]}" "${PASSTHROUGH[@]}"
  echo "wrote ${json_out}"
  echo
}

run_one "ligero" "${LIGERO_BIN}"
run_one "aurora" "${AURORA_BIN}"

echo "Done. Human-readable console output above; JSON: ${OUT_DIR}/ligero.json and ${OUT_DIR}/aurora.json"
