# Policy labels from a file in the policy directory (the default, /etc/portcullis/policies),
# named by the container's portcullis.policy-file label.
policy_dir=/etc/portcullis/policies
install -d -m 700 "${policy_dir}"
rm -f "${policy_dir}/pc-e2e-missing"
printf '%s\n' '# the private endpoint' \
  'portcullis.egress.private=ip:198.51.100.4,tcp:80' \
  'portcullis.egress.typo=ip:198.51.100.4/99,tcp:80' \
  'portcullis.icc.mode=deny' \
  | install -m 600 /dev/stdin "${policy_dir}/pc-e2e-app"

event "a missing policy file is reported" \
  "event=warning kind=policy_file container~${PROJECT}-broken" \
  dc restart -t 0 broken
event "an invalid value in a policy file is reported" \
  "event=warning kind=invalid_label container~${PROJECT}-app message~portcullis.egress.typo" \
  dc --profile late up -d app
flush_checks
wait_managed "$(svc_ip app net)" "$(svc_ip broken net)"

allowed "a destination of the policy file" tcp app 198.51.100.4 80
allowed "a destination of a label next to the file" tcp app 198.51.100.3 80
blocked "nothing else is opened" tcp app 198.51.100.5 80
blocked "the file's ICC mode" tcp app "$(svc_ip peer net)" 5432
blocked "a missing policy file denies even what labels allow" tcp broken 198.51.100.3 80
blocked "a missing policy file denies other containers" tcp broken "$(svc_ip peer net)" 5432
flush_checks

# Warnings, unlike connection events, never have the file's values.
no_values_in_warnings() {
  ! grep -F '"event":"warning"' "${ALERT_LOG}" | grep -F '198.51.100.4'
}
check "the file's values aren't in warnings" no_values_in_warnings
flush_checks
rm -f "${policy_dir}/pc-e2e-app"
