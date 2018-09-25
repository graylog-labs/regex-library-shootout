package org.graylog.labs.regexshootout;

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableRangeSet;
import com.google.common.collect.Range;
import com.google.common.collect.RangeSet;
import com.google.common.io.LineProcessor;
import com.google.common.io.Resources;
import com.google.common.net.InetAddresses;
import java.io.IOException;
import java.math.BigInteger;
import java.net.UnknownHostException;
import java.util.List;
import javax.annotation.Nonnull;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OperationsPerInvocation;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

public class IpSubnetRanges {
  private static final byte[] MASK_IPV4 = {-1, -1, -1, -1};
  private static final byte[] MASK_IPV6 = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

  // TODO ineffecient
  private static BigInteger ipToNumeric(String ip) {
    final BigInteger mask;
    final byte[] address = InetAddresses.forString(ip).getAddress();
    if (address.length == 4) {
      mask = (new BigInteger(1, MASK_IPV4)).not().shiftRight(32);
    } else {
      mask = (new BigInteger(1, MASK_IPV6)).not().shiftRight(128);
    }

    final BigInteger ipVal = new BigInteger(1, address);

    return ipVal.and(mask);
  }

  @Fork(value = 1, warmups = 1)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @OperationsPerInvocation(100_000)
  @Warmup(iterations = 5)
  @Measurement(iterations = 5)
  public void rangeSets(Plan plan, Blackhole blackhole) {
    for (String randomIp : plan.randomIps) {
      blackhole.consume(plan.subnetRanges.contains(ipToNumeric(randomIp)));
    }
  }

  @SuppressWarnings("UnstableApiUsage")
  @State(Scope.Benchmark)
  public static class Plan {

    RangeSet<BigInteger> subnetRanges;
    List<String> randomIps;

    @Setup(value = Level.Trial)
    public void initTrial() throws IOException {
      subnetRanges =
          Resources.readLines(
              Resources.getResource("bogon-networks.txt"),
              Charsets.UTF_8,
              new LineProcessor<RangeSet<BigInteger>>() {
                private ImmutableRangeSet.Builder<BigInteger> ranges = ImmutableRangeSet.builder();

                public boolean processLine(@Nonnull String line) {
                  if (line.trim().startsWith("#")) {
                    return true;
                  }
                  try {
                    final IpSubnet ipSubnet = new IpSubnet(line);
                    final Range<BigInteger> subnetRange =
                        Range.closed(ipSubnet.getStartIpNumeric(), ipSubnet.getEndIpNumeric());
                    ranges.add(subnetRange);
                  } catch (UnknownHostException e) {
                    throw new RuntimeException(e);
                  }
                  return true;
                }

                public RangeSet<BigInteger> getResult() {
                  return ranges.build();
                }
              });

      randomIps = Resources.readLines(Resources.getResource("random-ips.txt"), Charsets.UTF_8);
    }
  }
}
