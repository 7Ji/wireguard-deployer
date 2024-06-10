#!/bin/bash
# $1: the folder to look up for to-be-deployed tarballs
# $2...: [name]:[ssh name] pairs, or [name] for automatical [ssh name]
#   e.g. bash send-deploy.sh ~/Security/deployed.d hk1 cm2 l3a fuo:fuo.fuckblizzard.com
#     this would deploy hk1.tar to ssh://hk1
#                       cm2.tar to ssh://cm2
#                       l3a.tar to ssh://l3a
#                       fuo.tar to ssh://fuo.fuckblizzard.com

cd "$1"
tar_names=()
remotes=()
for arg in "${@:2}"; do
    tar_name=configs/"${arg%:*}".tar
    remote="${arg##*:}"
    [[ -z "${remote}" ]] && remote="${arg}"
    tar_names+=("${tar_name}")
    remotes+=("${remote}")
done
count="${#tar_names[@]}"
if [[ "${count}" -eq 0 ]]; then
    echo "Please specify names to deploy"
    exit 1
fi
echo "Going to deploy config and keys under '$1' to the following hosts:"
i=0
while [[ "${i}" -lt "${count}" ]]; do
    echo "${tar_names[$i]} => ${remotes[$i]}"
    let i++
done
echo "Press enter to confirm"
read _
i=0
while [[ "${i}" -lt "${count}" ]]; do
    tar_name="${tar_names[$i]}"
    remote="${remotes[$i]}"
    echo "=> Deploying: ${tar_name} => ${remote}"
    ssh "${remote}" 'sudo tar -C /etc/systemd/network -xv && sudo systemctl restart systemd-networkd' < "${tar_name}"
    echo "=> Deployed: ${tar_name} => ${remote}"
    let i++
done