'''
This is script used to download OPA executables of varied versions and operating systems.

Run python download_opa.py -h to see arguments

Minimum OPA version supported: 0.42.2
'''
import urllib.request
import hashlib
import argparse
import ssl

OPA_VERSION_SHA256_HASHES = {
    '0.45.0': {
        'windows': '31b12b954900584e8aa9103235adf192dd4c92e0039416eaec7d84e2f66fcf3e',
        'macos': '1d76713a65c11771bd86fe44d8ace17d79f1660e5bb00219d4f3c9b0f966f6e5',
        'linux': 'fb17d142d05c371e668440b414e41ccffc90c1e3d8f4984cf0c08e64fdd99a03'
    },
    '0.46.3': {
        'windows': '7ce4b97f2718a0af9f3796d36c12c4d12196e778ddf8b49679263a14c918150f',
        'macos': 'd1f2a921a45863ab1e98a5af012d107a3b3a280ba34fbb3a83bdce249d1ecece',
        'linux': '6c9c5294518d2be672a57fd8e1701405d0ebd7691ace3114b3c123331885d383'
    },
    '0.47.4': {
        'windows': '1f4285c743949b9c52ec644334ea315972fa4a200b5239c4ed1932ee6968e20d',
        'macos': 'b84ccf9608706e1496051442c866f5b755684033b6913eaab1870f9baadfd69e',
        'linux': '563f8f8146dbcccb22d8f98968c180db51fc8c9d3c2a1290ad93959859945886'
    },
    '0.48.0': {
        'windows': 'e27c533ca9c9a7a44064f879bcfccd327a95d6c84002f0d422137ffe62bd493f',
        'macos': '1554312fe5376ed8c34aa6404b85a1d3722971e7d5b8950f1888e62821ab73e3',
        'linux': 'ba2dcf3e0902f1c2da46679e30c5ceb2abefd6a1d5aa4bf3839426317dc28b7f'
    },
    '0.49.2': {
        'windows': 'de3f5406783f7e2cd98251e0801fb7184acc5ee6c2618748b88d68c3c6cec521',
        'macos': 'bcb69f7b01a70b7c1fd1d165142e0329c1e746bcfdf1cf2590613aa90f49557f',
        'linux': '40ed9de929162b13caf7b2d064f4c653c12a1a8cd15b80627cfb8d8fef5a4fc0'
    },
    '0.50.2': {
        'windows': '6c88953e54f4b5b2bd5189740a4718a61065c8f4b79df845a20c5ae5d150e8e5',
        'macos': '3d3c4ba4da7697606b1784ffa74a528902edb76726648f1de0539c83393e0250',
        'linux': '5697d0260cc7da8f15be195e61a2025907f3149a1dd5f84e0003ed9e9dea4970'
    },
    '0.51.0': {
        'windows': '34be29ebbcf256dc87f00ce91792e53edbf5ab631e31b14b8b712b70c50921da',
        'macos': '6b7c30eed9204409bc240091da560199343d731f3ed90947a19152d471621cfb',
        'linux': '9aef4d16e07f4169d22068c21a2d3559d193fee439364992e0f45fc3745ac5fd'
    },
    '0.52.0': {
        'windows': '6f0a952ebd0fd544bf27a13686a0f3494e9be102654a58996bedfe3bcc6f61ab',
        'macos': 'f40c0f2d4f864b09e30a30bb66ae3d1610405927176caffa12531aaf80dcbd53',
        'linux': 'a3ff21f3b16632d3868e49bdb52f6affbd97ec382d5310d1bbbe7627e8e5c8f6'
    },
    '0.53.1': {
        'windows': '3b8c30bb7a2df3f9f5e89dfbc1a963fb2aca2c646b8f697dd9fb95efd36b1b40',
        'macos': '73a76e498c1f9ec0442787efa056599fc11845301e4e3f03f436be6c31c3f7aa',
        'linux': '54e58abab85d125038152476f7c7987d352ca314c5e49e1f10d8e6800e6f6bef'
    },
    '0.54.0': {
        'windows': '25284b69e1dd7feaa17446e49b1085b61dca0b496dc868304153eb64b422c7eb',
        'macos': 'a33e829306cd2210ed743da7f4f957588ea350a184bb6ecbb7cbfd77ae7ca401',
        'linux': '633829141f8d6706ac24e0b84393d7730a975a17cc4a15790bf7fad959a28ec3'
    },
    '0.55.0': {
        'windows': '23b4300fc0e9a9af7c5cf6f955e91e3dd34edfe6b40e2ffca480f892f0538101',
        'macos': '4513f3bbb07c5915a7b5b70c951012327f9c1b6491b1ebab98d83149528599db',
        'linux': '388af161328871b943306f1ba7948658810a9fcf9c3c0a27bdfac6e8086617a9'
    },
    '0.56.0': {
        'windows': '8b2aab7e968245b178c2480e4843ad8d0b6551283306a9ce155545b2f72782db',
        'macos': 'f46e1a37bf6e3ad98523bd12ad51fe3b9f1ea660dfb3e9131ae1c84eece6dd57',
        'linux': '623771025227588898af1788998d5b5f29068a887682cd8b8e9699136d4cf121'
    },
    '0.57.1': {
        'windows': '9a6d3ef2279760efbcead6a7095393e04adaa1be3c7458eb62a2b79d93df4bc3',
        'macos': '54a2d229638baddb0ac6f7c283295e547e6f491ab2ddcaf714fa182427e8421d',
        'linux': '59e8c6ef9ae2f95b76aa79344eb81ca6f3950a0fd7a23534c4d7065f42fda99f'
    },
    '0.58.0': {
        'windows': 'da61c5745c545b64047efe6c5a730f38f63dfa1d07c29e1f1297fe235a28ddd7',
        'macos': 'c9b11f32e2adcb0783275be0f1ee69c2d78b3496b4992d64a3f41f4f3f678685',
        'linux': '7bb75b14c9bcb5798d42bed5fc45c438ee5bb783894733ce553ba3445f66034f'
    },
    '0.59.0': {
        'windows': '0167f2bd69b72993ccdca222d0bc5d9278ffb194f9c87fddc1b55ecc9edf17df',
        'macos': '3edddc7dded91a7b2fe7fbe3d862778dccc28eff6ee515c41b38d65474d5e9f4',
        'linux': '5f615343a1cae1deb2f2f514b2f4b46456495fe1c828b17e779eb583aced0cc3'
    },
    '0.60.0': {
        'windows': '8e20b4fcd6b8094be186d8c9ec5596477fb7cb689b340d285865cb716c3c8ea7',
        'macos': '1b96cb23a63700b75f670e6bca1e3f8e9e7930c29b095753a9f978ce88828fa0',
        'linux': '7d7cb45d9e6390646e603456503ca1232180604accc646de823e4d2c363dbeb0'
    }
}

def download_file(url, filename, disablessl):
    '''
    Downloads a file from the given url

    :param url: The url we are downloading the file from
    :param filename: The name of the output file
    '''

    # pylint: disable=protected-access
    context = ssl._create_unverified_context() if disablessl else None

    with urllib.request.urlopen(url, context=context) as response:
        file_size = int(response.headers["Content-Length"])
        downloaded_size = 0
        block_size = 1024  # 1 KB
        mb_size = 1024 * 1024


        file_size_mb = file_size / mb_size
        with open(filename, 'wb') as file:
            while True:
                buffer = response.read(block_size)
                if not buffer:
                    break

                file.write(buffer)
                downloaded_size += len(buffer)
                downloaded_size_mb = downloaded_size / mb_size
                print(f'Download Progress: \
                        {downloaded_size_mb:.2f}/{file_size_mb:.2f} MB' , end='\r')

            print(f"\nDownload is complete. OPA executable is named: {filename}")


def verify_hash(filename, expected_hash):
    '''
    Checks if the SHA256 Hash of a file matches an expected SHA256 Hash

    :param filename: The file we're hashing
    :param expected_hash: The SHA256 hash we're expecting the file to hash to
    '''
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as file:
        while True:
            data = file.read(65536)
            if not data:
                break
            sha256.update(data)
    file_hash = sha256.hexdigest()
    return file_hash == expected_hash

def main():
    '''
    Takes in user arguments for downloading an OPA executable
    '''
    supported_opa_versions = list(OPA_VERSION_SHA256_HASHES)
    parser = argparse.ArgumentParser(add_help = True,
                                     description="Download executable the OPA executable" \
                                     " file required to run this SCuBA tool.")
    parser.add_argument('-v', default='0.59.0', choices=supported_opa_versions,
                        help='What version of OPA to download: Default version: 0.59.0')
    parser.add_argument('-os', default='windows', choices=['windows', 'macos', 'linux'],
                        help='Operating system version of OPA to download. Default os: windows')
    parser.add_argument('--disablessl', action='store_true',
                        help='If there are proxy errors,\
                        try adding this switch to disable ssl verification')

    args = parser.parse_args()
    base_url = 'https://openpolicyagent.org/downloads/'
    base_url = base_url + "v" + args.v + "/"
    filename_base = 'opa'

    if args.os == 'windows':
        url = base_url + 'opa_windows_amd64.exe'
        filename = filename_base + '_windows_amd64.exe'
    elif args.os == 'macos':
        url = base_url + 'opa_darwin_amd64'
        filename = filename_base + '_darwin_amd64'
    elif args.os == 'linux':
        url = base_url + 'opa_linux_amd64_static'
        filename = filename_base + '_linux_amd64_static'
    else:
        raise ValueError('Invalid operating system. Please provide a valid OS (windows, macos, '\
            'or linux)')

    try:
        expected_hash = OPA_VERSION_SHA256_HASHES[args.v][args.os]
    except Exception as exc:
        print("Untested OPA version the download will continue but hash verification will fail."\
              "Proceed with caution", exc)
        expected_hash = 'thisShallFail'

    try:
        print(f"Downloading OPA executable version {args.v} for {args.os}",)
        download_file(url, filename, args.disablessl)
    except Exception as exc:
        print("An exception occurred while trying to download the OPA executable. " \
        "This may be due to a proxy error." \
        "Please retry or see the README for how to manually download OPA", exc)

    try:
        print('Verifying SHA256 hash...')
        if verify_hash(filename, expected_hash):
            print("File hash verified successfully." \
                  " You are ready to start running this SCuBA Tool with OPA")
        else:
            print("File hash verification failed." \
            "The downloaded file may be corrupted or " \
            "has not been verified by us. " \
            "See instructions for downloading OPA manually if you verify the file is corrupted. " \
            "Proceed with caution.")
    except Exception as exc:
        print("An exception occurred while trying to verify OPA hash." \
        "The file may be corrupted or currently not supported.", exc)

if __name__ == '__main__':
    main()
