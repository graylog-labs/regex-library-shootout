package org.graylog.labs.regexshootout;

import static org.graylog.labs.regexshootout.IpSubnetRanges.ipToNumeric;
import static org.junit.Assert.assertEquals;

import com.gliwka.hyperscan.wrapper.Expression;
import com.gliwka.hyperscan.wrapper.Match;
import com.gliwka.hyperscan.wrapper.Scanner;
import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableListMultimap;
import com.google.common.collect.Multimaps;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.graylog.labs.regexshootout.Hyperscan.PlanMultimatch;
import org.graylog.labs.regexshootout.Hyperscan.PlanSinglematch;
import org.junit.Test;

public class Tests {

  private static final int NUMBER_OF_BOGONS = 14319;

  private static String getMatches(List<Match> scan) {
    final ImmutableListMultimap<Expression, Match> matchedExpressions =
        Multimaps.index(scan, Match::getMatchedExpression);
    final StringBuilder sb = new StringBuilder();
    for (Entry<Expression, Collection<Match>> match : matchedExpressions.asMap().entrySet()) {
      sb.append(match.getKey().getContext()).append(" : [");
      Joiner.on(", ")
          .appendTo(
              sb,
              match.getValue().stream().map(Match::getEndPosition).collect(Collectors.toList()));
      sb.append("]");
    }
    return sb.toString();
  }

  @Test
  public void hyperscan() throws IOException {
    final Hyperscan.Plan plan = new PlanMultimatch();
    plan.initTrial();

    int matches = 0;
    try (Scanner scanner = new Scanner()) {
      scanner.allocScratch(plan.database);
      for (String ip : plan.randomIps) {
        try {
          final List<Match> scan = scanner.scan(plan.database, ip);
          if (!scan.isEmpty()) {
            // debug: System.out.println(ip + " : " + getMatches(scan));
            matches++;
          }
        } catch (Throwable throwable) {
          throwable.printStackTrace();
        }
      }
    } catch (Throwable e) {
      throw new RuntimeException(e);
    }

    assertEquals(NUMBER_OF_BOGONS, matches);
  }

  @Test
  public void hyperscanSingle() throws IOException {
    final Hyperscan.Plan plan = new PlanSinglematch();
    plan.initTrial();

    int matches = 0;
    try (Scanner scanner = new Scanner()) {
      scanner.allocScratch(plan.database);
      for (String ip : plan.randomIps) {
        try {
          final List<Match> scan = scanner.scan(plan.database, ip);
          if (!scan.isEmpty()) {
            matches++;
          }
        } catch (Throwable throwable) {
          throwable.printStackTrace();
        }
      }
    } catch (Throwable e) {
      throw new RuntimeException(e);
    }

    assertEquals(NUMBER_OF_BOGONS, matches);
  }

  @Test
  public void javaUtilIteration() throws IOException {
    final JavaUtilRegex.Plan plan = new JavaUtilRegex.Plan();
    plan.initTrial();

    int matches = 0;
    for (Pattern pattern : plan.database) {
      for (String randomIp : plan.randomIps) {

        if (pattern.matcher(randomIp).matches()) {
          matches++;
        }
      }
    }

    assertEquals(NUMBER_OF_BOGONS, matches);
  }

  @Test
  public void javaUtilAlternation() throws IOException {
    final JavaUtilRegex.Plan plan = new JavaUtilRegex.Plan();
    plan.initTrial();

    int matches = 0;
    for (String randomIp : plan.randomIps) {
      if (plan.combinedPattern.matcher(randomIp).matches()) {
        matches++;
      }
    }

    assertEquals(NUMBER_OF_BOGONS, matches);
  }

  @Test
  public void subnetRanges() throws IOException {
    final IpSubnetRanges.Plan plan = new IpSubnetRanges.Plan();
    plan.initTrial();

    int matches = 0;
    for (String randomIp : plan.randomIps) {
      if (plan.subnetRanges.contains(ipToNumeric(randomIp))) {
        matches++;
      }
    }

    assertEquals(NUMBER_OF_BOGONS, matches);
  }
}
