package org.graylog.labs.regexshootout;

import com.gliwka.hyperscan.wrapper.Database;
import com.gliwka.hyperscan.wrapper.Expression;
import com.gliwka.hyperscan.wrapper.ExpressionFlag;
import com.gliwka.hyperscan.wrapper.Match;
import com.gliwka.hyperscan.wrapper.Scanner;
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.io.LineProcessor;
import com.google.common.io.Resources;
import java.io.IOException;
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

public class Hyperscan {

  @Fork(value = 1, warmups = 1)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @OperationsPerInvocation(100_000)
  @Warmup(iterations = 5)
  @Measurement(iterations = 5)
  public void regexMatchesMulti(PlanMultimatch plan, Blackhole blackhole) {
    try (Scanner scanner = new Scanner()) {
      scanner.allocScratch(plan.database);
      for (String ip : plan.randomIps) {
        try {
          final List<Match> matches = scanner.scan(plan.database, ip);
          blackhole.consume(matches);
        } catch (Throwable throwable) {
          throwable.printStackTrace();
        }
      }
    } catch (Throwable e) {
      throw new RuntimeException(e);
    }
  }

  @Fork(value = 1, warmups = 1)
  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @OperationsPerInvocation(100_000)
  @Warmup(iterations = 5)
  @Measurement(iterations = 5)
  public void regexMatchesSingle(PlanSinglematch plan, Blackhole blackhole) {
    try (Scanner scanner = new Scanner()) {
      scanner.allocScratch(plan.database);
      for (String ip : plan.randomIps) {
        try {
          final List<Match> matches = scanner.scan(plan.database, ip);
          blackhole.consume(matches);
        } catch (Throwable throwable) {
          throwable.printStackTrace();
        }
      }
    } catch (Throwable e) {
      throw new RuntimeException(e);
    }
  }

  @SuppressWarnings("UnstableApiUsage")
  @State(Scope.Benchmark)
  public abstract static class Plan {

    Database database;
    List<String> randomIps;

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
              new LineProcessor<Database>() {
                private final ImmutableList.Builder<Expression> regexps = ImmutableList.builder();

                public boolean processLine(@Nonnull String line) {
                  if (line.trim().startsWith("#")) {
                    return true;
                  }
                  regexps.add(createExpression("^" + line));
                  return true;
                }

                public Database getResult() {
                  try {
                    return Database.compile(regexps.build());
                  } catch (Throwable throwable) {
                    throwable.printStackTrace();
                    return null;
                  }
                }
              });

      randomIps = Resources.readLines(Resources.getResource("random-ips.txt"), Charsets.UTF_8);
    }

    protected abstract Expression createExpression(@Nonnull String line);
  }

  public static class PlanMultimatch extends Plan {

    @Override
    protected Expression createExpression(@Nonnull String line) {
      return new Expression(line, line);
    }
  }

  public static class PlanSinglematch extends Plan {

    @Override
    protected Expression createExpression(@Nonnull String line) {
      return new Expression(line, ExpressionFlag.SINGLEMATCH, line);
    }
  }
}
