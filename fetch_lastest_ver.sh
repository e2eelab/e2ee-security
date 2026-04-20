#!/bin/bash
# Load version of latest tag from e2ee-security
clean_ver() {
  ver=$1
  if [[ $ver == v* ]]; then
    # remove v prefix
    echo ${ver#"v"}
  else
    echo $ver
  fi
}

version=""
pushd protos/src/e2ees > /dev/null
  git fetch origin > /dev/null 2>&1
  git pull --no-commit --rebase=false --log origin master > /dev/null 2>&1
popd > /dev/null
git fetch origin > /dev/null 2>&1
version=$(git describe --abbrev=0 --tags $(git rev-list --tags --max-count=1))
git checkout "$version" > /dev/null 2>&1
version=$(clean_ver $version)

echo $version