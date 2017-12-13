# Sorcery
---
*Sorcery* is a tool for working with data sources (hosts/protected hosts/logs sources) configured with [Alert Logic Cloud Defender](https://www.alertlogic.com/). It supports various operations like purging defunct hosts from the configuration, naming sources and assigning protected hosts to appliances. This tool is designed to make it possible to automate these operations.

## Implementation Details
- Original design and implementation by Michael Gupton (mgupton@alertlogic.com).
- Implemented in Python 3.x and tested with 3.6.
- Uses the *requests* package.
- Uses the *docopt* package.
- Uses the Cloud Defender public API and requires an API key from Alert Logic.
  - Contact support@alertlogic.com to request an API key. Or go [here](https://www.alertlogic.com/resources/alert-logic-activeintegration-apis/).
  - Contact Alert Logic support at support@alertlogic.com to get the data center and customer id.
- Some of the commands are designed to be ran on the host itself. These commands automatically determine the identity of the host and perform the specified operations. `sorcery host name-me` is an example of this type of command.
- Some of the commands can be ran from any place. `sorcery hosts purge-defunct` is an example of this type of command.

## Usage
### General Form of Commands

```
python sorcery.py <command> <subcommand> <option-1> ... <option-N>
```
- Every command requires options for the API key (--api_key), the data center designation (--dc) and the customer id (--cid).

### Options
```
Options:
  --help -h            Show this help screen.
  --api_key=<key>      Alert Logic public API key.
  --dc=<dc>            Data center where the Alert Logic account is provisioned (Options: denver | ashburn | newport).
  --cid=<cid>          Alert Logic customer account.
  --status=<status>    Return only phosts/sources with the specified status [default: offline]
  --age=<age>          Number of days offline a source must be to be considered defunct [default: 7]
  --tag=<tag>          Only apply command to sources with the specified tag.
```
### Commmand: sorcery host purge-defunct
This command will delete all defunct hosts(log sources and protected hosts) from the Cloud Defender configuration. A defunct host is defined as one that has been offline for some specified number of days. The default value is 7 days.

- This command can be ran from any host that has Internet connectivity.

```
python sorcery.py host purge-defunct --api_key=<key> --dc=<dc> --cid=<cid> [--age=<age>] [--tag=<tag>]
```

### Command: sorcery host name-me
This command will identify the host it is running on and then name the source in Cloud Defender with the specified name. For AWS instances and Azure VMs the hardcoded behavior of the agent is to name a source with the instance/VM id. This command could be used to name sources with some other value, like the host name.
```
python sorcery.py host name-me --api_key=<key> --dc=<dc> --cid=<cid> --name=<name>
```
```
python sorcery.py host name-me --api_key=abc123 --dc=ashburn --cid=123 --name=${hostname}
```
### Command: sorcery host assign-me
This command will identify the host it is running on and then assign the protected host to an appliance via the specified assignment policy.
```
python sorcery.py host assign-me --api_key=<key> --dc=<dc> --cid=<cid> --policy-name=<policy-name>
```

## Miscellanea
- Sorcery could be "frozen" or distributed as a single self-contained executable by using ``pyinstaller --onefile`` to avoid the external depencies on the Python runtime and packages.
