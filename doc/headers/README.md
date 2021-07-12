# Classifying function headers

Function headers consist of a function name followed by the parameter types in parentheses.
As a crude heuristics, the bash script `classify.sh` uses regex-based rules to group function headers into categories.

Usage:
```bash
classify.sh <headers> <rules-1> <rules-2> ...
```

`<headers>` is a text file with one function header per line.

`<rules-i>` is a text file with one rule per line. Each rule has the form
```
<inclusion pattern>   <category>   <exclusion pattern (optional)>
```
A header is assigned to `<category>` if it matches `<inclusion pattern>` but not `<exclusion pattern>`.

`classify.sh` works in rounds. Initially, all rules in `<rules-1>` are applied simultaneously to the headers in `<headers>`.
If a rule classifies a header as belonging to `<category>`, the header is added to the file `categories/<category>`.
One header may end up in several categories, if several rules match.
At the end of the round, all headers newly classified in this round are removed from the set of headers.
Then `<rules-2>` is applied to the remaining headers, and so on.
After the last round, all classified headers are merged into a single file `categories.csv` that contains each header with its category, separated by a semicolon.

## Required files

```
headers/classify.sh
headers/rules1.txt
headers/rules2.txt
```

## Try it out

```bash
cd ethutils/doc/headers  # go to the directory with the sample data
bash wrapper_classify.sh # apply classify.sh to sample headers
```

The file `headers.csv` contains 71673 headers from the contracts on Ethereum's main chain.
After running the scripts, `categories.csv` contains the classified headers followed by their category.

