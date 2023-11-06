# The `aft` config
The `aft` config is a very simple and minimal config file. It's filename is `.config`, and it should be edited by the user.

## Format
The format is very basic, and it's followed by the following rule: `key\s?=\s?value`. `key` and `value` would be discussed in the next section. Every option needs to be on a separate line.

## Options
The config file only has 3 options:
- `verbose=i`: where `i` is 1-3 where 3 is the most verbose and 1 is the least. `verbose=1` prints only errors; `verbose=2` prints errors and info; `verbose=3` prints any log possible.
- `mode=mode`: where `mode` can be one of the following: `relay || download || receiver || sender`.
- `identifier=string`: where `string` MUST BE a fixed string length of 10. This is used with relays to identify a receiver.

## Example
```
verbose=3
identifier=usertester
```
