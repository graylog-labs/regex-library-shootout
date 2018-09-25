Simplistic benchmark to get a grip on how fast or slow it is to check 100k random IPs against
the roughly 3000 CIDR pattern long bogon list.

Four implementations are compared:

* naive java.util.regex.Pattern
   * this loops over all compiled regexes and over all IPs to be checked
   * dead slow
* one giant java.util.regex.Pattern
   * simply the alternation of all CIDR patterns
   * about an order of magnitude faster
* one Hyperscan database of all CIDR patterns
   * another order of magnitude faster
* convert CIDR patterns into BigInteger start/stop ranges
  * check numeric BigInteger ip in a RangeSet.contains() call


On my machine (Dell XPS 9560, i7 2.8GHz, default JVM settings):

```
# Run complete. Total time: 00:13:30

Benchmark                   Mode  Cnt        Score        Error  Units
Hyperscan.regexMatches     thrpt    5   312537.505 ±  11774.398  ops/s
IpSubnetRanges.rangeSets   thrpt    5  1577815.808 ± 111092.311  ops/s
JavaUtilRegex.alternation  thrpt    5    73775.253 ±   4067.587  ops/s
JavaUtilRegex.iteration    thrpt    5     2843.513 ±     72.267  ops/s

```

