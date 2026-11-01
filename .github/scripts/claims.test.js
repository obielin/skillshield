// Tests for claims.js. Run with: node --test .github/scripts/claims.test.js
const test = require("node:test");
const assert = require("node:assert/strict");
const claims = require("./claims.js");

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse("2026-11-20T12:00:00Z");
const ago = (days) => new Date(NOW - days * DAY).toISOString();
const label = (name) => ({ name });

// A fake GitHub client. `issue` is what issues.get returns now; `claimsOf`
// lists each user's open assigned issues; `timelines` holds issue timelines.
// `afterAssign` lets a test change the world as the assignment lands, to
// simulate another command running at the same time.
function fakeGithub({
  issue = {}, merged = {}, claimsOf = {}, timelines = {}, assignAccepted = true, afterAssign, staleIssues = [],
} = {}) {
  const calls = { comments: [], added: [], removed: [] };
  const current = { number: 30, state: "open", labels: [], assignees: [], ...issue };
  const github = {
    rest: {
      search: {
        issuesAndPullRequests: async ({ q }) => {
          const user = (q.match(/author:(\S+)/) || [])[1];
          return { data: { total_count: merged[user] || 0 } };
        },
      },
      issues: {
        get: async () => ({ data: current }),
        createComment: async ({ issue_number, body }) => calls.comments.push({ issue_number, body }),
        addAssignees: async ({ assignees }) => {
          calls.added.push(...assignees);
          if (!assignAccepted) return { data: { assignees: current.assignees } };
          for (const login of assignees) {
            current.assignees.push({ login });
            (timelines[30] ||= []).push({ event: "assigned", assignee: { login }, created_at: new Date(NOW).toISOString() });
            (claimsOf[login] ||= []).push({ number: 30, labels: current.labels });
          }
          if (afterAssign) afterAssign({ current, timelines, claimsOf });
          return { data: { assignees: current.assignees } };
        },
        removeAssignees: async ({ issue_number, assignees }) => calls.removed.push({ issue_number, assignees }),
        listForRepo: "listForRepo",
        listEventsForTimeline: "listEventsForTimeline",
      },
    },
    paginate: async (fn, args) => {
      if (fn === "listForRepo") return args.assignee === "*" ? staleIssues : claimsOf[args.assignee] || [];
      return timelines[args.issue_number] || [];
    },
  };
  return { github, calls };
}

function ctx({ body = "", user = "newbie", pr = false, bot = false } = {}) {
  return {
    repo: { owner: "obielin", repo: "skillshield" },
    payload: {
      issue: { number: 30, ...(pr ? { pull_request: {} } : {}) },
      comment: { body, user: { login: bot ? "x[bot]" : user, type: bot ? "Bot" : "User" } },
    },
  };
}

test("parseCommand reads only a command at the start of the first line", () => {
  assert.equal(claims.parseCommand("/assign"), "assign");
  assert.equal(claims.parseCommand("  /ASSIGN please\nthanks"), "assign");
  assert.equal(claims.parseCommand("/unassign"), "unassign");
  assert.equal(claims.parseCommand("/extend"), "extend");
  assert.equal(claims.parseCommand("I'd like to /assign this"), null);
  assert.equal(claims.parseCommand("/assignment"), null);
  assert.equal(claims.parseCommand(""), null);
});

test("a newcomer can claim a good first issue", async () => {
  const { github, calls } = fakeGithub({ issue: { labels: [label("good first issue")] } });
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "/assign" }) }), "assigned");
  assert.deepEqual(calls.added, ["newbie"]);
  assert.deepEqual(calls.removed, []);
  assert.match(calls.comments[0].body, /it's yours/);
});

test("the decision uses the issue as it is now, not the comment's snapshot", async () => {
  // The comment payload says nothing about assignees; the live issue is taken.
  const { github, calls } = fakeGithub({ issue: { assignees: [{ login: "someone" }] } });
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "/assign" }) }), "taken");
  assert.deepEqual(calls.added, []);
  assert.match(calls.comments[0].body, /@someone/);
});

test("someone with a merged PR cannot take a good first issue", async () => {
  const { github, calls } = fakeGithub({ issue: { labels: [label("good first issue")] }, merged: { newbie: 1 } });
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "/assign" }) }), "not-first-timer");
  assert.deepEqual(calls.added, []);
  assert.match(calls.comments[0].body, /help wanted/);
});

test("a newcomer holds one good first issue at a time", async () => {
  const { github, calls } = fakeGithub({
    issue: { labels: [label("good first issue")] },
    claimsOf: { newbie: [{ number: 12, labels: [label("good first issue")] }] },
  });
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "/assign" }) }), "one-first-timer-issue");
  assert.deepEqual(calls.added, []);
});

test("anyone can claim a help wanted issue, up to three open claims", async () => {
  const two = [{ number: 1, labels: [] }, { number: 2, labels: [] }];
  const ok = fakeGithub({ issue: { labels: [label("help wanted")] }, merged: { newbie: 5 }, claimsOf: { newbie: [...two] } });
  assert.equal(await claims.handleComment({ github: ok.github, context: ctx({ body: "/assign" }) }), "assigned");
  const full = fakeGithub({ issue: { labels: [label("help wanted")] }, claimsOf: { newbie: [...two, { number: 3, labels: [] }] } });
  assert.equal(await claims.handleComment({ github: full.github, context: ctx({ body: "/assign" }) }), "too-many");
  assert.deepEqual(full.calls.added, []);
});

test("if another claim lands first at the same time, ours is undone", async () => {
  const { github, calls } = fakeGithub({
    afterAssign: ({ current, timelines }) => {
      current.assignees.unshift({ login: "fast" });
      timelines[30].unshift({ event: "assigned", assignee: { login: "fast" }, created_at: ago(0.001) });
    },
  });
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "/assign" }) }), "lost-race");
  assert.deepEqual(calls.removed, [{ issue_number: 30, assignees: ["newbie"] }]);
  assert.match(calls.comments[0].body, /just before you/);
});

test("two claims in the same second leave exactly one claimant", () => {
  const same = { alice: 1000, bob: 1000 };
  // Each run asks "did the other claim first?" and must get opposite answers.
  assert.equal(claims.claimedFirst("alice", "bob", same), true);
  assert.equal(claims.claimedFirst("bob", "alice", same), false);
  assert.equal(claims.claimedFirst("bob", "alice", { alice: 2000, bob: 1000 }), true);
});

test("in a same-second tie, the run for the later login undoes its claim", async () => {
  const sameSecond = new Date(NOW).toISOString();
  const run = (user, other) => {
    const fake = fakeGithub({
      afterAssign: ({ current, timelines }) => {
        current.assignees.push({ login: other });
        timelines[30] = [
          { event: "assigned", assignee: { login: "alice" }, created_at: sameSecond },
          { event: "assigned", assignee: { login: "bob" }, created_at: sameSecond },
        ];
      },
    });
    return claims.handleComment({ github: fake.github, context: ctx({ body: "/assign", user }) });
  };
  assert.equal(await run("alice", "bob"), "assigned");
  assert.equal(await run("bob", "alice"), "lost-race");
});

test("claims made on two issues at once cannot exceed the limit", async () => {
  const two = [{ number: 1, labels: [] }, { number: 2, labels: [] }];
  const { github, calls } = fakeGithub({
    claimsOf: { newbie: [...two] },
    afterAssign: ({ claimsOf }) => claimsOf.newbie.push({ number: 31, labels: [] }), // a parallel /assign on #31
  });
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "/assign" }) }), "too-many");
  assert.deepEqual(calls.removed, [{ issue_number: 30, assignees: ["newbie"] }]);
});

test("roadmap tracking issues and closed issues cannot be claimed", async () => {
  const a = fakeGithub({ issue: { labels: [label("roadmap")] } });
  assert.equal(await claims.handleComment({ github: a.github, context: ctx({ body: "/assign" }) }), "not-claimable");
  const b = fakeGithub({ issue: { state: "closed" } });
  assert.equal(await claims.handleComment({ github: b.github, context: ctx({ body: "/assign" }) }), "closed");
  assert.deepEqual([...a.calls.added, ...b.calls.added], []);
});

test("pull requests, bots and ordinary comments are ignored", async () => {
  const { github, calls } = fakeGithub();
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "/assign", pr: true }) }), "ignored");
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "/assign", bot: true }) }), "ignored");
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "Looks good to me" }) }), "ignored");
  assert.deepEqual(calls.comments, []);
});

test("/unassign releases only your own claim", async () => {
  const mine = fakeGithub({ issue: { assignees: [{ login: "newbie" }] } });
  assert.equal(await claims.handleComment({ github: mine.github, context: ctx({ body: "/unassign" }) }), "unassigned");
  assert.deepEqual(mine.calls.removed, [{ issue_number: 30, assignees: ["newbie"] }]);
  const theirs = fakeGithub({ issue: { assignees: [{ login: "someone" }] } });
  assert.equal(await claims.handleComment({ github: theirs.github, context: ctx({ body: "/unassign" }) }), "not-assignee");
  assert.deepEqual(theirs.calls.removed, []);
});

test("a failed assignment is reported instead of claimed", async () => {
  const { github, calls } = fakeGithub({ assignAccepted: false });
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "/assign" }) }), "assign-failed");
  assert.match(calls.comments[0].body, /maintainer will assign/);
});

const staleIssue = (number, logins, labels = []) => ({
  number, assignees: [].concat(logins).map((login) => ({ login })), labels: labels.map(label),
});
const assigned = (login, days) => ({ event: "assigned", assignee: { login }, actor: { login: "github-actions[bot]", type: "Bot" }, created_at: ago(days) });
const commented = (login, days, body = "working on it", type = "User") => ({ event: "commented", actor: { login, type }, created_at: ago(days), body });
const botReminder = (forLogin, days) => commented("github-actions[bot]", days, `${claims.reminderMarker(forLogin)}\nchecking in`, "Bot");

test("a claim idle for 14 days is released", async () => {
  const { github, calls } = fakeGithub({ staleIssues: [staleIssue(1, "newbie")], timelines: { 1: [assigned("newbie", 15)] } });
  assert.deepEqual(await claims.releaseStale({ github, context: ctx(), now: NOW }), [{ issue: 1, user: "newbie", action: "released" }]);
  assert.deepEqual(calls.removed, [{ issue_number: 1, assignees: ["newbie"] }]);
});

test("a claim idle for 10 days gets one reminder, not two", async () => {
  const first = fakeGithub({ staleIssues: [staleIssue(1, "newbie")], timelines: { 1: [assigned("newbie", 11)] } });
  assert.deepEqual(await claims.releaseStale({ github: first.github, context: ctx(), now: NOW }), [{ issue: 1, user: "newbie", action: "reminded" }]);
  assert.ok(first.calls.comments[0].body.includes(claims.reminderMarker("newbie")));
  const again = fakeGithub({ staleIssues: [staleIssue(1, "newbie")], timelines: { 1: [assigned("newbie", 12), botReminder("newbie", 1)] } });
  assert.deepEqual(await claims.releaseStale({ github: again.github, context: ctx(), now: NOW }), []);
});

test("a reminder for one assignee, or a copied marker, does not count for another", async () => {
  const { github } = fakeGithub({
    staleIssues: [staleIssue(1, ["alice", "bob"])],
    timelines: {
      1: [
        assigned("alice", 11), assigned("bob", 11),
        botReminder("alice", 0.5),
        commented("mallory", 0.5, claims.reminderMarker("bob")), // not a bot
      ],
    },
  });
  assert.deepEqual(await claims.releaseStale({ github, context: ctx(), now: NOW }), [{ issue: 1, user: "bob", action: "reminded" }]);
});

test("a comment made while the release job runs keeps the claim", async () => {
  let reads = 0;
  const { github, calls } = fakeGithub({ staleIssues: [staleIssue(1, "newbie")] });
  github.paginate = async (fn) => {
    if (fn === "listForRepo") return [staleIssue(1, "newbie")];
    reads += 1;
    return reads === 1 ? [assigned("newbie", 20)] : [assigned("newbie", 20), commented("newbie", 0)];
  };
  assert.deepEqual(await claims.releaseStale({ github, context: ctx(), now: NOW }), []);
  assert.deepEqual(calls.removed, []);
});

test("a recent comment, an open PR, the maintainer or a roadmap issue keeps the claim", async () => {
  const openPr = { event: "cross-referenced", created_at: ago(20), source: { issue: { pull_request: {}, state: "open" } } };
  const { github, calls } = fakeGithub({
    staleIssues: [staleIssue(1, "newbie"), staleIssue(2, "newbie"), staleIssue(3, "obielin"), staleIssue(4, "newbie", ["roadmap"])],
    timelines: {
      1: [assigned("newbie", 30), commented("newbie", 2)],
      2: [assigned("newbie", 30), openPr],
      3: [assigned("obielin", 60)],
      4: [assigned("newbie", 60)],
    },
  });
  assert.deepEqual(await claims.releaseStale({ github, context: ctx(), now: NOW }), []);
  assert.deepEqual(calls.removed, []);
});
