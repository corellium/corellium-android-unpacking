# Android Unpacking Automation

A bit of automation strung up around an Android 7.1.2 device on Corellium, used to defeating (most) packers on the market. 

## Description
This method targets `art::DexFile::OpenMemory` method for Android 7.1.12 while utilizing a Corellium device to provide an always-on and always-ready device for unpacking. While this current demo only utilized one device, this can essentially be scaled up transparently to the front end as all the "tasks" are handled by `nsqd`.

The `backend` sets up a vpn tunnel to the Corellium server, which auto-restarts upon failure, and opens up a reverse proxy to the docker network. This is then utilized by the `unpacker-worker` which uses it to communicate transparently with the device.

## Building

### Setup
 - Have a corellium account with a device already created and booted up (7.1.2 eng build)
 - Replace `backend/vpn-profile.ovpn` with the OpenVPN profile from your Corellium device
 - Fill out `.env` file like so;

```
INSTANCE_ID=7cc6ca2a-6622-479b-aa4b-8394aa9d9475-instance-for-unpacker
CORELLIUM_URL=testinstance.corellium.com
CORELLIUM_USERNAME=unpackeruser
CORELLIUM_PASSWORD=unpackerpassword

GIN_MODE=debug
SERVE_PORT=3000
ADB_PROXY=5555
```

### Docker

Then simply use `docker-compose build` followed by `docker-compose up`.

## Usage

Hitting the backend api with an apk will result in it queing up a binary to get unpacked;
`curl 0.0.0.0:3000/unpack/SHA1_OF_APK --data-binary @/path/to/apk`

After a minute or two, check back for the asset status;
`curl 0.0.0.0:3000/unpack/SHA1_OF_APK/status`

Then when assets of interest are found, download them;
`curl 0.0.0.0:3000/unpack/SHA1_OF_APK/SHA1_OF_ASSET`

## Disclaimer
This presentation and code are meant for education and research purposes only. Do as you please with it, but accept any and all responsibility for your actions. The tools were created specifically to assist in malware reversing and analysis - be careful. They have not been hardened for external public consumption, it is likely not a smart idea to expose a service like this to the public internet without thinking long and hard about it.

## License
```
Copyright 2020 Tim 'diff' Strazzere <tim@corellium.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
