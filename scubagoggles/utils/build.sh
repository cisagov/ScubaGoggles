#!/usr/bin/env bash

# This is the build procedure for creating both the wheel and source (.tar.gz)
# distribution files for ScubaGoggles.  For a clean build process, this
# procedure does the following:
#
#  1. Creates a new Python virtual environment for the build.
#  2. Creates a new Git clone of the ScubaGoggles repository.  Optionally,
#     the specified branch or version tag is checked out.
#  3. Using the clone from the previous step, installs ScubaGoggles in
#     the build virtual environment.
#  4. Builds the ScubaGoggles package distribution files and copies them
#     to a destination directory.
#  5. Cleans up the virtual environment and repository directories that were
#     created for the build process.
#
# The directories are created in the invoking user's temporary directory.
# This script will attempt to clean these up before exiting, but they will
# ultimately get cleaned up by the temporary directory management process
# used by the operating system.
#
# What's left after this script completes are the two distribution files
# (.whl & .tar.gz) for the ScubaGoggles package.  They are copied to the
# user's working directory when this script was invoked, or the directory
# specified in the options.
#
# General users should install the wheel distribution.  Anyone interested in
# ScubaGoggles development may be interested in the source distribution.

set -e
shopt -s expand_aliases

gitTag=
outDir="$PWD"
scubaGogglesGit='git@github.com:cisagov/ScubaGoggles.git'
zipSource=true

usage()
{
  printf 'script usage: %s [options]\n\n' "$(basename "$0")" >&2
  printf '    -h: display usage and exit\n'
  printf '    -o <dir>: create package files in this directory\n'
  printf '              (creates directory if non-existent)\n'
  printf '              defaults to %s\n' "$outDir"
  printf '    -r <git-repo>: ScubaGoggles Git repository specification\n'
  printf '              defaults to %s\n' "$scubaGogglesGit"
  printf '    -t <git-tag-or-branch>: checkout tag or branch for build\n'
  printf '                            defaults to top of main branch\n'
  printf '    -x: omit the ZIP source distribution file\n'
}

while getopts ':ho:r:t:x' option
do
  case "$option" in
    h)
      usage
      exit
      ;;
    o)
      outDir=$(realpath "$OPTARG")
      mkdir -p "$outDir"
      ;;
    r)
      scubaGogglesGit="$OPTARG"
      ;;
    t)
      gitTag=$OPTARG
      ;;
    x)
      zipSource=false
      ;;
    ?)
      usage
      exit 1
      ;;
  esac
done

shift $((OPTIND -1))

[ "$*" ] && usage && exit 1

# Used to distinguish output from this script.
buildPfx='{build>>>}'

cleanup()
{
  echo "$buildPfx Performing build cleanup..."
  [[ $(type -t deactivate) == function ]] && deactivate
  [[ "${DIRSTACK[0]}" == "$scubaGoggles" ]] && popd
  rm -rf "$scubaEnv"
  rm -rf "$scubaGoggles"
}

generateSourceZip()
{
  # Generates a ZIP file version of the source code distribution, which is
  # in gzipped tar format (.tar.gz).  There are 2 parameters to this function:
  #
  #     generateSourceZip <gz-tar-file> <out-var-name>
  #
  # where <gz-tar-file> is an existing source distribution (the file must
  # end with ".tar.gz" (not ".tgz")), and <out-var-name> is the name of the
  # variable where the output file name will be written.  The ZIP source
  # code file will be created in the same location as the given tar file.
  #
  # Python's PEP 517 has restricted the source distributions built by
  # backends to be gzipped tar files only.
  #
  # This work is done in a temporary directory, which is removed provided
  # that no errors occur during the creation of the ZIP file.

  local gztarFile
  local sourceTemp
  local -n outFile=$2

  gztarFile=$1
  sourceTemp=$(mktemp -d -t scubagoggles_src.XXXXXXXXXX)
  outFile=$(realpath "${gztarFile/tar.gz/zip}")

  tar xfz "$gztarFile" -C "$sourceTemp"

  pushd "$sourceTemp"

  zip -qr "$outFile" .

  popd

  rm -rf "$sourceTemp"
}

pushd() { builtin pushd "$@" > /dev/null; }

popd() { builtin popd > /dev/null; }

if [[ "$OSTYPE" == 'msys' || "$OSTYPE" == 'cygwin' ]]
then
  # This is Windows (via Git Bash (msys) or Cygwin).
  venvSubdir='Scripts'
else
  # Assumed to be linux variant (including macOS).
  # python3 must be defined to invoke the correct Python version.
  venvSubdir='bin'
  alias python=python3
fi

scubaEnv=$(mktemp -d -t scuba-env.XXXXXXXXXX)

scubaGoggles=$(mktemp -d -t scubagoggles.XXXXXXXXXX)

trap cleanup EXIT

echo "$buildPfx Creating new Python virtual environment for build..."

python -m venv "$scubaEnv"

echo "$buildPfx Cloning Git repository..."

git clone "$scubaGogglesGit" "$scubaGoggles"

pushd "$scubaGoggles"

if [[ -n "$gitTag" ]]
then
  echo "$buildPfx Checkout $gitTag"
  git checkout "$gitTag"
fi

echo "$buildPfx Activate Python virtual environment..."

source "$scubaEnv/$venvSubdir/activate"

echo "$buildPfx Install requirements and editable ScubaGoggles..."

pip install -r requirements.txt

pip install -e .

echo "$buildPfx Build distribution files..."

python -m build

wheelFile=$(realpath dist/scubagoggles-*.whl)
tarFile=$(realpath dist/scubagoggles-*.tar.gz)

packageFiles=("$wheelFile" "$tarFile")

if [ "$zipSource" == true ]
then
  echo "$buildPfx Generating Source ZIP File..."
  generateSourceZip "$tarFile" zipFile
  packageFiles+=("$zipFile")
fi

for file in "${packageFiles[@]}"
do
  echo "$buildPfx Copying $file to $outDir"
  cp "$file" "$outDir/$(basename "$file")"
done
