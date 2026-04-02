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
pushd protos/src/e2ees
  git fetch origin
  git pull --no-commit --rebase=false --log origin master
popd
#git fetch origin
#git pull --no-commit --rebase=false --log origin master
git fetch origin
version=$(git describe --abbrev=0 --tags $(git rev-list --tags --max-count=1))
git checkout "$version"
version=$(clean_ver $version)

echo $version