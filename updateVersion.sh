#!/bin/bash
echo "{new_release_version}={$1}" >> $GITHUB_OUTPUT
sed -i "s#<PackageVersion>.*#<PackageVersion>$1</PackageVersion>#" $2
sed -i "s#<Version>.*#<Version>$1</Version>#" $2
