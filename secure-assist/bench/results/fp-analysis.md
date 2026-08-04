# Where the OWASP false positives come from

Every OWASP case the tool flags as vulnerable but the benchmark labels safe, classified by the mechanism that makes it safe. Generated from the benchmark cache; no inference involved.

## sqli (CWE-89)

157 of 212 safe cases flagged (74.1%).

| Mechanism | Cases | Share |
|---|---|---|
| Reflection | 128 | 82% |
| Collection key indirection | 12 | 8% |
| Switch on a folded constant | 11 | 7% |
| Always-taken arithmetic branch | 5 | 3% |
| Encoding round-trip | 1 | 1% |

## cmdi (CWE-78)

63 of 105 safe cases flagged (60.0%).

| Mechanism | Cases | Share |
|---|---|---|
| Reflection | 47 | 75% |
| Collection key indirection | 10 | 16% |
| Switch on a folded constant | 3 | 5% |
| Always-taken arithmetic branch | 3 | 5% |

## pathtraver (CWE-22)

63 of 114 safe cases flagged (55.3%).

| Mechanism | Cases | Share |
|---|---|---|
| Reflection | 51 | 81% |
| Switch on a folded constant | 7 | 11% |
| Collection key indirection | 5 | 8% |

## Combined

283 of 431 safe cases across the three taint categories were flagged.

| Mechanism | Cases | Share |
|---|---|---|
| Reflection | 226 | 80% |
| Collection key indirection | 27 | 10% |
| Switch on a folded constant | 21 | 7% |
| Always-taken arithmetic branch | 8 | 3% |
| Encoding round-trip | 1 | 0% |

## Representative cases

One example per mechanism, quoted verbatim. In each, `param` is attacker-controlled and `bar` is what reaches the sink.

### Switch on a folded constant — `BenchmarkTest00191` (sqli)

The branch is selected by a compile-time-constant expression, so the tainted arm is unreachable.

```java
String bar;
String guess = "ABC";
char switchTarget = guess.charAt(1); // condition 'B', which is safe
// Simple case statement that assigns param to bar on conditions 'A', 'C', or 'D'
switch (switchTarget) {
    case 'A':
        bar = param;
        break;
    case 'B':
        bar = "bob";
        break;
    case 'C':
    case 'D':
        bar = param;
        break;
    default:
        bar = "bob's your uncle";
        break;
}
```

### Collection key indirection — `BenchmarkTest00197` (sqli)

The tainted value is stored in a map or list under one key and read back under another.

```java
String bar = "alsosafe";
if (param != null) {
    java.util.List<String> valuesList = new java.util.ArrayList<String>();
    valuesList.add("safe");
    valuesList.add(param);
    valuesList.add("moresafe");
    valuesList.remove(0); // remove the 1st safe value
    bar = valuesList.get(1); // get the last 'safe' value
}
```

### Reflection — `BenchmarkTest00332` (sqli)

The value passes through a reflective call, so the taint is only traceable by resolving the reflection target.

```java
String bar = thing.doSomething(g40477); // reflection
```

### Always-taken arithmetic branch — `BenchmarkTest00333` (sqli)

A condition over integer literals is always true, so the tainted assignment never executes.

```java
String bar;
// Simple ? condition that assigns constant to bar on true condition
int num = 106;
bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
```

### Encoding round-trip — `BenchmarkTest00930` (sqli)

The value is encoded and decoded, leaving it unchanged but obscuring the flow.

```java
String bar = "";
if (param != null) {
    bar =
            new String(
                    org.apache.commons.codec.binary.Base64.decodeBase64(
                            org.apache.commons.codec.binary.Base64.encodeBase64(
                                    param.getBytes())));
}
try {
```
