
t = db.index_check6;
t.drop();

function keysExamined(query, hint) {
    var explain = t.find(query).hint(hint).explain("executionStats");
    return explain.executionStats.totalKeysExamined;
}

t.ensureIndex({age: 1, rating: 1});

for (var age = 10; age < 50; age++) {
    for (var rating = 0; rating < 10; rating++) {
        t.save({age: age, rating: rating});
    }
}

assert.eq(10, keysExamined({age: 30}, {}), "A");
assert.eq(20, keysExamined({age: {$gte: 29, $lte: 30}}, {}), "B");
assert.eq(19,
          keysExamined({age: {$gte: 25, $lte: 30}, rating: {$in: [0, 9]}}, {age: 1, rating: 1}),
          "C1");
assert.eq(24,
          keysExamined({age: {$gte: 25, $lte: 30}, rating: {$in: [0, 8]}}, {age: 1, rating: 1}),
          "C2");
assert.eq(29,
          keysExamined({age: {$gte: 25, $lte: 30}, rating: {$in: [1, 8]}}, {age: 1, rating: 1}),
          "C3");

assert.eq(5,
          keysExamined({age: {$gte: 29, $lte: 30}, rating: 5}, {age: 1, rating: 1}),
          "C");  // SERVER-371
assert.eq(
    7,
    keysExamined({age: {$gte: 29, $lte: 30}, rating: {$gte: 4, $lte: 5}}, {age: 1, rating: 1}),
    "D");  // SERVER-371

assert.eq.automsg("2",
                  "t.find( { age:30, rating:{ $gte:4, $lte:5} } )" + ".explain('executionStats')" +
                      ".executionStats.totalKeysExamined");

t.drop();

for (var a = 1; a < 10; a++) {
    for (var b = 0; b < 10; b++) {
        for (var c = 0; c < 10; c++) {
            t.save({a: a, b: b, c: c});
        }
    }
}

function doQuery(count, query, sort, index) {
    var explain = t.find(query).hint(index).sort(sort).explain("executionStats");
    var nscanned = explain.executionStats.totalKeysExamined;
    assert(Math.abs(count - nscanned) <= 2);
}

function doTest(sort, index) {
    doQuery(1, {a: 5, b: 5, c: 5}, sort, index);
    doQuery(2, {a: 5, b: 5, c: {$gte: 5, $lte: 6}}, sort, index);
    doQuery(1, {a: 5, b: 5, c: {$gte: 5.5, $lte: 6}}, sort, index);
    doQuery(1, {a: 5, b: 5, c: {$gte: 5, $lte: 5.5}}, sort, index);
    doQuery(3, {a: 5, b: 5, c: {$gte: 5, $lte: 7}}, sort, index);
    doQuery(4, {a: 5, b: {$gte: 5, $lte: 6}, c: 5}, sort, index);
    if (sort.b > 0) {
        doQuery(3, {a: 5, b: {$gte: 5.5, $lte: 6}, c: 5}, sort, index);
        doQuery(3, {a: 5, b: {$gte: 5, $lte: 5.5}, c: 5}, sort, index);
    } else {
        doQuery(3, {a: 5, b: {$gte: 5.5, $lte: 6}, c: 5}, sort, index);
        doQuery(3, {a: 5, b: {$gte: 5, $lte: 5.5}, c: 5}, sort, index);
    }
    doQuery(8, {a: 5, b: {$gte: 5, $lte: 7}, c: 5}, sort, index);
    doQuery(5, {a: {$gte: 5, $lte: 6}, b: 5, c: 5}, sort, index);
    if (sort.a > 0) {
        doQuery(3, {a: {$gte: 5.5, $lte: 6}, b: 5, c: 5}, sort, index);
        doQuery(3, {a: {$gte: 5, $lte: 5.5}, b: 5, c: 5}, sort, index);
        doQuery(3, {a: {$gte: 5.5, $lte: 6}, b: 5, c: {$gte: 5, $lte: 6}}, sort, index);
    } else {
        doQuery(3, {a: {$gte: 5.5, $lte: 6}, b: 5, c: 5}, sort, index);
        doQuery(3, {a: {$gte: 5, $lte: 5.5}, b: 5, c: 5}, sort, index);
        doQuery(4, {a: {$gte: 5.5, $lte: 6}, b: 5, c: {$gte: 5, $lte: 6}}, sort, index);
    }
    doQuery(8, {a: {$gte: 5, $lte: 7}, b: 5, c: 5}, sort, index);
    doQuery(7, {a: {$gte: 5, $lte: 6}, b: 5, c: {$gte: 5, $lte: 6}}, sort, index);
    doQuery(7, {a: 5, b: {$gte: 5, $lte: 6}, c: {$gte: 5, $lte: 6}}, sort, index);
    doQuery(11, {a: {$gte: 5, $lte: 6}, b: {$gte: 5, $lte: 6}, c: 5}, sort, index);
    doQuery(15, {a: {$gte: 5, $lte: 6}, b: {$gte: 5, $lte: 6}, c: {$gte: 5, $lte: 6}}, sort, index);
}

for (var a = -1; a <= 1; a += 2) {
    for (var b = -1; b <= 1; b += 2) {
        for (var c = -1; c <= 1; c += 2) {
            t.dropIndexes();
            var spec = {a: a, b: b, c: c};
            t.ensureIndex(spec);
            doTest(spec, spec);
            doTest({a: -a, b: -b, c: -c}, spec);
        }
    }
}
