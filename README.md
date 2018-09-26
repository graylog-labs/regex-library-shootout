Simplistic benchmark to get a grip on how fast or slow it is to check 100k random IPs against
the roughly 3000 CIDR pattern long bogon list.

Five implementations are compared:

* naive java.util.regex.Pattern
   * this loops over all compiled regexes and over all IPs to be checked
   * dead slow
* one giant java.util.regex.Pattern
   * simply the alternation of all CIDR patterns
   * about an order of magnitude faster
* one Hyperscan database of all CIDR patterns
   * another order of magnitude faster
   * two variants: with and without `SINGLEMATCH` option
* convert CIDR patterns into BigInteger start/stop ranges
  * check numeric BigInteger ip in a RangeSet.contains() call
  * can still be optimized to use `long` for IPv4 addresses


On my machine (Dell XPS 9560, i7 2.8GHz, default JVM settings):

```
# Run complete. Total time: 00:11:29

Benchmark                      Mode  Cnt        Score        Error  Units
Hyperscan.regexMatchesMulti   thrpt    5   472497.086 ± 120152.258  ops/s
Hyperscan.regexMatchesSingle  thrpt    5   515623.166 ± 176015.019  ops/s
IpSubnetRanges.rangeSets      thrpt    5  2037209.457 ± 515291.444  ops/s
JavaUtilRegex.alternation     thrpt    5    89526.016 ±  35312.328  ops/s
JavaUtilRegex.iteration       thrpt    5     3515.186 ±     33.760  ops/s
```

