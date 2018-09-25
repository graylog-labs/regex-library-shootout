Simplistic benchmark to get a grip on how fast or slow it is to check 100k random IPs against
the roughly 3000 CIDR pattern long bogon list.

Three implementations are compared:

* naive java.util.regex.Pattern
 * this loops over all compiled regexes and over all IPs to be checked
 * dead slow
* one giant java.util.regex.Pattern
 * simply the alternation of all CIDR patterns
 * about an order of magnitude faster
* one Hyperscan database of all CIDR patterns
 * another order of magnitude faster


On my machine (Dell XPS 9560, i7 2.8GHz, default JVM settings):

```
# Run complete. Total time: 00:10:03

Benchmark                   Mode  Cnt       Score       Error  Units
Hyperscan.regexMatches     thrpt    5  410218.252 ± 16671.505  ops/s
JavaUtilRegex.alternation  thrpt    5   95313.538 ±  4528.887  ops/s
JavaUtilRegex.iteration    thrpt    5    3785.416 ±    20.848  ops/s
```

