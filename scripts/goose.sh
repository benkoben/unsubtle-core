#!/usr/bin/env bash

set -o nounset
set -o pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
target_module_dir=$(realpath "${script_dir}/../sql/schema")
mode=""

print_usage() {
  echo "Usage: $0 -m <mode>"
  echo "  -m <mode>   Specify the mode: 'up' or 'down'"
}

while getopts ":m:" opt; do
  case ${opt} in
    m )
      mode=$OPTARG
      if [[ "$mode" != "up" && "$mode" != "down" ]]; then
        echo "Error: Invalid mode '$mode'. Must be 'up' or 'down'."
        print_usage
        exit 1
      fi
      ;;
    \? )
      echo "Invalid option: -$OPTARG" >&2
      print_usage
      exit 1
      ;;
    : )
      echo "Option -$OPTARG requires an argument." >&2
      print_usage
      exit 1
      ;;
  esac
done

if [[ -z ${mode} ]]; then
      print_usage
      exit 1
fi

pushd "${target_module_dir}"
goose postgres "postgres://postgres:@localhost:5432/unsubtle" "${mode}"
popd

echo "Done :)"