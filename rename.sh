#!/bin/bash

set -eux

rename "s/$1/$2/g" $(find ./ -type f | grep -vE '\.git|\.swp')
find ./ -type f | grep -vE '\.git|\.swp' | xargs sed -i -e "s/$1/$2/g"
