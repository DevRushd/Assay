// Package eval runs the labelled corpus through the mechanics engine and
// records the result.
//
// It exists to make two things measurable that the aggregate eval cannot:
//
//   - Per-check judgment (#115). A report is correct if its aggregate level is
//     right, but a wrong check can be masked by aggregation: a capability check
//     that says clear and a reputation escalation that raises the level to
//     critical produce a correct report for the wrong reason. Per-check labels
//     measure each check's output on its own.
//   - Cross-version movement (#116). Recording the output of one version and
//     diffing it against another shows which subjects moved, and in which
//     field, instead of only whether the aggregate expectations still pass.
//
// Nothing here touches the network: every subject is rebuilt from fixtures
// captured from live sources under the mechanics testdata directory.
package eval
