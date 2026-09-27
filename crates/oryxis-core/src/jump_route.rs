//! The dial route of a host whose hops sit behind hops of their own
//! (issue #184). Lives here, beside the model, because every dialler
//! needs the SAME answer: the app's `make_jump_resolver` and the MCP
//! server's dial plan both expand through it, so a host reachable from
//! a tab is reachable over MCP by the same route.

use crate::models::connection::Connection;

/// Flatten `chain` into the full dial route, following each hop's own
/// `jump_chain` recursively (issue #184): each hop contributes its own
/// route immediately before itself, so a bastion that sits behind a
/// bastion is reached the way OpenSSH reaches a `ProxyJump` hop whose
/// config names another jump. Pure over the connection list so it
/// unit-tests without an app.
///
/// `target_id` seeds the visited set, and a hop already routed earlier
/// in the list is never routed twice: a cycle (or a hop naming the
/// target itself) degrades to dialing the hop directly instead of
/// recursing forever. Dangling ids stay in the route verbatim, so the
/// engine still reports "jump host not found" for them like before.
pub fn expanded_jump_chain(
    target_id: uuid::Uuid,
    chain: &[uuid::Uuid],
    connections: &[Connection],
) -> Vec<uuid::Uuid> {
    fn push_route(
        id: uuid::Uuid,
        connections: &[Connection],
        visited: &mut std::collections::HashSet<uuid::Uuid>,
        out: &mut Vec<uuid::Uuid>,
    ) {
        if !visited.insert(id) {
            return;
        }
        if let Some(hop) = connections.iter().find(|c| c.id == id) {
            for pre in &hop.jump_chain {
                push_route(*pre, connections, visited, out);
            }
        }
        out.push(id);
    }
    let mut visited = std::collections::HashSet::new();
    visited.insert(target_id);
    let mut out = Vec::new();
    for id in chain {
        push_route(*id, connections, &mut visited, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::expanded_jump_chain;
    use crate::models::connection::Connection;
    use uuid::Uuid;

    fn host(label: &str, chain: Vec<Uuid>) -> Connection {
        let mut c = Connection::new(label.to_string(), label);
        c.jump_chain = chain;
        c
    }

    #[test]
    fn nested_hop_route_expands_before_the_hop() {
        // C jumps via B, and B itself sits behind A (issue #184): the
        // dial route must reach B through A, the way OpenSSH follows
        // B's own ProxyJump.
        let a = host("a", vec![]);
        let b = host("b", vec![a.id]);
        let target = Uuid::new_v4();
        let route = expanded_jump_chain(target, &[b.id], &[a.clone(), b.clone()]);
        assert_eq!(route, vec![a.id, b.id]);

        // One level deeper: A behind Z.
        let z = host("z", vec![]);
        let a2 = host("a2", vec![z.id]);
        let b2 = host("b2", vec![a2.id]);
        let route = expanded_jump_chain(target, &[b2.id], &[z.clone(), a2.clone(), b2.clone()]);
        assert_eq!(route, vec![z.id, a2.id, b2.id]);
    }

    #[test]
    fn hop_already_routed_is_not_dialed_twice() {
        // The final host lists the full route by hand (today's
        // workaround) AND B names A itself: A must appear once.
        let a = host("a", vec![]);
        let b = host("b", vec![a.id]);
        let target = Uuid::new_v4();
        let route = expanded_jump_chain(target, &[a.id, b.id], &[a.clone(), b.clone()]);
        assert_eq!(route, vec![a.id, b.id]);
    }

    #[test]
    fn cycles_degrade_to_a_direct_dial_of_the_hop() {
        // B's own chain names the target: expanding must not recurse
        // into it, the hop is dialed directly.
        let target = Uuid::new_v4();
        let b = host("b", vec![target]);
        let route = expanded_jump_chain(target, &[b.id], std::slice::from_ref(&b));
        assert_eq!(route, vec![b.id]);

        // A and B name each other: the walk terminates and every hop
        // still appears exactly once.
        let mut a = host("a", vec![]);
        let mut b = host("b", vec![]);
        a.jump_chain = vec![b.id];
        b.jump_chain = vec![a.id];
        let route = expanded_jump_chain(target, &[b.id], &[a.clone(), b.clone()]);
        assert_eq!(route, vec![a.id, b.id]);

        // The chain naming the target itself contributes nothing.
        let route = expanded_jump_chain(target, &[target], &[]);
        assert!(route.is_empty());
    }

    #[test]
    fn dangling_hop_ids_survive_verbatim() {
        // A hop id with no row (deleted host, unsynced peer) stays in
        // the route so the engine reports it, exactly like before.
        let ghost = Uuid::new_v4();
        let b = host("b", vec![ghost]);
        let target = Uuid::new_v4();
        let route = expanded_jump_chain(target, &[b.id], std::slice::from_ref(&b));
        assert_eq!(route, vec![ghost, b.id]);
    }
}
