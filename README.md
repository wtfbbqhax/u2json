# u2json 

Convert Snort unified2 logs into JSON.

## Dependencies

To build u2json you must install the following dependencies:

- libunified2
- Jansson

## Installation

1. Install with brew.

```bash
brew tap wtfbbqhax/homebrew-ap
brew install u2json
```

2. Intall from source

```bash
# git clone https://github.com/wtfbbqhax/libunified2
# cd libunified2
# autoreconf -fi
# ./configure
# make install

git clone https://github.com/wtfbbqhax/u2json
cd u2json/
autoreconf -fi
./configure
make install
```

## Usage

u2json currently takes only 2 arguments, this will change in future releases as new functionality is introduced.

```bash
$ u2json snort-unified.log <CNT>
```

CNT is an optional number of records to read from the file `snort-unified.log`. 

Omitting CNT will dump the entire file into JSON.

## Examples

Convert a single record to json. (pretty printed with `jq`).

```bash
$ u2json ./alerts.log 1 | jq -M
[
  {
    "Event": {
      "sensor_id": 0,
      "generator_id": 1,
      "mpls_label": 0,
      "classification_id": 15,
      "dport_icode": 4662,
      "event_id": 1,
      "packet_action": 32,
      "event_second": 1285763793,
      "event_microsecond": 246590,
      "signature_id": 17322,
      "signature_revision": 1,
      "priority_id": 1,
      "ip_source": "10.1.50.1",
      "ip_destination": "10.1.60.1",
      "sport_itype": 57832,
      "protocol": 6,
      "vlan_id": 0,
      "policy_id": 65
    }
  }
]
```

Filter out Packet records

```bash
$ u2json ./snort-unified.log  | jq '.[].Packet'
{
  "packet_data": "\\x00\\x50\\x56\\xC0\\x00\\x01\\x00\\x50\\x56\\xC0\\x00\\x00\\x08\\x00\\x45\\x00\\x02\\x8A\\x67\\xED\\x40\\x00\\x80\\x06\\x0E\\x7D\\x0A\\x01\\x32\\x01\\x0A\\x01\\x3C\\x01\\xE1\\xE8\\x12\\x36\\xB3\\x77\\x98\\xF2\\xB6\\x07\\x3B\\x98\\x80\\x18\\x00\\xB7\\x39\\x22\\x00\\x00\\x01\\x01\\x08\\x0A\\x02\\x9E\\xFF\\x1D\\x00\\x03\\x56\\x26\\xE3\\x3D\\x00\\x00\\x00\\x01\\xEE\\x4F\\x08\\xE3\\x00\\x0E\\xAE\\x41\\xB0\\x24\\x89\\x38\\x1C\\xC7\\x6F\\x6E\\x00\\x00\\x00\\x00\\xAF\\x8D\\x04\\x00\\x00\\x00\\x02\\x01\\x00\\x01\\x04\\x00\\x74\\x65\\x73\\x74\\x03\\x01\\x00\\x11\\x3C\\x00\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\xEB\\x06\\x41\\x41\\xC6\\x14\\x00\\x10\\x33\\xD2\\x66\\x81\\xCA\\xFF\\x0F\\x42\\x52\\x6A\\x02\\x58\\xCD\\x2E\\x3C\\x05\\x5A\\x74\\xEF\\xB8\\xFF\\x67\\x1B\\xD3\\x8B\\xFA\\xAF\\x75\\xEA\\xAF\\x75\\xE7\\xFF\\xE7\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\xFF\\x67\\x1B\\xD3\\xFF\\x67\\x1B\\xD3\\x6A\\x48\\x59\\xD9\\xEE\\xD9\\x74\\x24\\xF4\\x58\\x81\\x70\\x13\\x4A\\x9C\\x69\\x48\\x83\\xE8\\xFC\\xE2\\xF4\\xB6\\xF6\\x82\\x05\\xA2\\x65\\x96\\xB7\\xB5\\xFC\\xE2\\x24\\x6E\\xB8\\xE2\\x0D\\x76\\x17\\x15\\x4D\\x32\\x9D\\x86\\xC3\\x05\\x84\\xE2\\x17\\x6A\\x9D\\x82\\x01\\xC1\\xA8\\xE2\\x49\\xA4\\xAD\\xA9\\xD1\\xE6\\x18\\xA9\\x3C\\x4D\\x5D\\xA3\\x45\\x4B\\x5E\\x82\\xBC\\x71\\xC8\\x4D\\x60\\x3F\\x79\\xE2\\x17\\x6E\\x9D\\x82\\x2E\\xC1\\x90\\x22\\xC3\\x15\\x80\\x68\\xA3\\x49\\xB0\\xE2\\xC1\\x26\\xB8\\x75\\x29\\x89\\xAD\\xB2\\x2C\\xC1\\xDF\\x59\\xC3\\x0A\\x90\\xE2\\x38\\x56\\x31\\xE2\\x08\\x42\\xC2\\x01\\xC6\\x04\\x92\\x85\\x18\\xB5\\x4A\\x0F\\x1B\\x2C\\xF4\\x5A\\x7A\\x22\\xEB\\x1A\\x7A\\x15\\xC8\\x96\\x98\\x22\\x57\\x84\\xB4\\x71\\xCC\\x96\\x9E\\x15\\x15\\x8C\\x2E\\xCB\\x71\\x61\\x4A\\x1F\\xF6\\x6B\\xB7\\x9A\\xF4\\xB0\\x41\\xBF\\x31\\x3E\\xB7\\x9C\\xCF\\x3A\\x1B\\x19\\xDF\\x3A\\x0B\\x19\\x63\\xB9\\x20\\xE6\\x8C\\x61\\x42\\x2C\\xF4\\x4E\\x47\\x2C\\xCF\\xE0\\xA9\\xDF\\xF4\\x85\\xB1\\xE0\\xFC\\x3E\\xB7\\x9C\\xF6\\x79\\x19\\x1F\\x63\\xB9\\x2E\\x20\\xF8\\x0F\\x20\\x29\\xF1\\x03\\x18\\x13\\xB5\\xA5\\xC1\\xAD\\xF6\\x2D\\xC1\\xA8\\xAD\\xA9\\xBB\\xE0\\x09\\xE0\\xB5\\xB4\\xDE\\x44\\xB6\\x08\\xB0\\xE4\\x32\\x72\\x37\\xC2\\xE3\\x22\\xEE\\x97\\xFB\\x5C\\x63\\x1C\\x60\\xB5\\x4A\\x32\\x1F\\x18\\xCD\\x38\\x19\\x20\\x9D\\x38\\x19\\x1F\\xCD\\x96\\x98\\x22\\x31\\xB0\\x4D\\x84\\xCF\\x96\\x9E\\x20\\x63\\x96\\x7F\\xB5\\x4C\\x01\\xAF\\x33\\x5A\\x10\\xB7\\x3F\\x98\\x96\\x9E\\xB5\\xEB\\x95\\xB7\\x9A\\xF4\\x17\\x90\\xA8\\xEF\\x3A\\xB7\\x9C\\x63\\xB9",
  "packet_second": 1285763793,
  "sensor_id": 0,
  "packet_microsecond": 246590,
  "event_id": 1,
  "linktype": 1,
  "event_second": 1285763793,
  "packet_length": 664
}
```

Filter for HTTP clients (destination port 80)

```bash
$ u2json ./snort-unified.log | jq '.[].Event as $Event | if ($Event.dport_icode == 80) then $Event else empty end'
{
  "signature_id": 19,
  "sensor_id": 0,
  "event_id": 9,
  "vlan_id": 0,
  "generator_id": 119,
  "event_second": 1285763815,
  "event_microsecond": 621315,
  "classification_id": 3,
  "ip_destination": "10.1.60.31",
  "signature_revision": 1,
  "priority_id": 2,
  "ip_source": "10.1.50.31",
  "mpls_label": 0,
  "sport_itype": 1035,
  "dport_icode": 80,
  "protocol": 6,
  "packet_action": 32,
  "policy_id": 65
}
```

## Known Bugs

u2json lacks support for Unified2ExtraData.

u2json/libunified2 have some valgrind warnings

## Planned features

1. JSON output of decoded packet headers. 

2. Monitor a directory, autodetect log rotation

3. Multiple input file(s)

4. Builtin "query" language to filter logs

5. Support for named pipes (created with `mkfifo`)
