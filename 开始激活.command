#!/bin/zsh
cd "$(dirname "$0")" || exit 1
./bin/lejav-gen-navicat activate
result=$?
if (( result != 0 )); then
  printf '\n流程已停止，请查看上方提示。按回车关闭窗口。'
  read -r
fi
exit "$result"
