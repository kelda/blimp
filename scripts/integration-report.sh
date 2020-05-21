#!/bin/bash
set -euo pipefail

stdout=$(mktemp)
stderr=$(mktemp)

# allow this command to fail without the whole script exiting
set +e
# run the test
$(dirname "${BASH_SOURCE[0]}")/integration-test.sh > "${stdout}" 2> "${stderr}"
status=$?
set -e

message="STATUS: ${status}
STDERR:
$(cat ${stderr})
STDOUT:
$(cat ${stdout})
"

rm "${stdout}" "${stderr}"

echo "${message}"

if [[ $status -eq 0 ]]; then
	# OK
	dd_status=0
else
	# CRITICAL
	dd_status=2
fi

dd_message='
{
  "check": "blimp.integration",
  "status": "'"${dd_status}"'",
  "message": .
}
'

jq --compact-output --slurp --raw-input "${dd_message}" <<< "${message}" | \
	curl -fsS -X POST 'https://api.datadoghq.com/api/v1/check_run?api_key=bf5fbd013ca4796d843ba0510cb5ee05' \
		 -H "Content-Type: application/json" \
		 -d @-
