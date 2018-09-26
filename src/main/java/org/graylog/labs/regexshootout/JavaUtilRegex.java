package org.graylog.labs.regexshootout;

import com.google.common.base.Charsets;
import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import com.google.common.io.LineProcessor;
import com.google.common.io.Resources;
import java.io.IOException;
import java.util.List;
import java.util.regex.MatchResult;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
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

public class JavaUtilRegex {

  @Fork(value = 1, warmups = 1)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @OperationsPerInvocation(100_000)
  @Warmup(iterations = 5)
  @Measurement(iterations = 5)
  public void iteration(Plan plan, Blackhole blackhole) {
    for (Pattern pattern : plan.database) {
      for (String randomIp : plan.randomIps) {

        final MatchResult matchResult = pattern.matcher(randomIp).toMatchResult();
        blackhole.consume(matchResult);
      }
    }
  }

  @Fork(value = 1, warmups = 1)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @OperationsPerInvocation(100_000)
  @Warmup(iterations = 5)
  @Measurement(iterations = 5)
  public void alternation(Plan plan, Blackhole blackhole) {
    for (String randomIp : plan.randomIps) {
      final MatchResult matchResult = plan.combinedPattern.matcher(randomIp).toMatchResult();
      blackhole.consume(matchResult);
    }
  }

  @SuppressWarnings("UnstableApiUsage")
  @State(Scope.Benchmark)
  public static class Plan {

    List<Pattern> database;
    List<String> randomIps;
    Pattern combinedPattern;

    @Setup(value = Level.Trial)
    public void initTrial() throws IOException {
      // read the preprocessed bogon network regexps.
      // original list is from https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt
      // converted with rgxg:
      // for pat in `grep -v ^\# src/main/resources/bogon-networks.txt`;
      //   do rgxg cidr $pat >> src/main/resources/bogon-networks-regexps.txt ;
      // done
      database =
          Resources.readLines(
              Resources.getResource("bogon-networks-regexps.txt"),
              Charsets.UTF_8,
              new LineProcessor<List<Pattern>>() {
                private final ImmutableList.Builder<Pattern> regexps = ImmutableList.builder();

                public boolean processLine(@Nonnull String line) {
                  if (line.trim().startsWith("#")) {
                    return true;
                  }
                  regexps.add(Pattern.compile("^" + line));
                  return true;
                }

                public List<Pattern> getResult() {
                  try {
                    return regexps.build();
                  } catch (Throwable throwable) {
                    throwable.printStackTrace();
                    return null;
                  }
                }
              });
      // build on huge pattern, using alternation, to mimic what Hyperscan does (but doing so
      // inefficiently)
      combinedPattern =
          Resources.readLines(
              Resources.getResource("bogon-networks-regexps.txt"),
              Charsets.UTF_8,
              new LineProcessor<Pattern>() {
                private final ImmutableList.Builder<String> regexps = ImmutableList.builder();

                @Override
                public boolean processLine(String line) throws IOException {
                  if (line.trim().startsWith("#")) {
                    return true;
                  }
                  regexps.add(line);
                  return true;
                }

                @Override
                public Pattern getResult() {
                  return Pattern.compile(
                      Joiner.on('|')
                          .join(
                              regexps
                                  .build()
                                  .stream()
                                  .map(pattern -> "^(?:" + pattern + ")")
                                  .collect(Collectors.toList())));
                }
              });
      randomIps = Resources.readLines(Resources.getResource("random-ips.txt"), Charsets.UTF_8);
    }
  }
}
