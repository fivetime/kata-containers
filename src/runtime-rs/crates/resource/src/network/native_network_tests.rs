// Copyright 2026 OpenStack Nova Kata contributors
// SPDX-License-Identifier: Apache-2.0
use super::*;

#[actix_rt::test]
#[ignore = "requires an isolated root network namespace"]
async fn native_tc_cleanup_preserves_peer_and_allows_recreate() {
    assert_eq!(
        std::env::var("NOVA_KATA_NETWORK_ISOLATED").as_deref(),
        Ok("1")
    );
    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    let worker = tokio::spawn(connection);
    let peer = "nkfixture0";
    let tap = "tap4242_kata";
    create_link(&handle, peer, 1).await.unwrap();
    let peer_index = get_link_by_name(&handle, peer).await.unwrap().attrs().index;
    for _ in 0..2 {
        let mut pair = NetworkPair::new(
            &handle,
            4242,
            peer,
            network_model::TC_FILTER_NET_MODEL_STR,
            1,
        )
        .await
        .unwrap();
        pair.add_network_model().await.unwrap();
        let expected = pair.virt_iface.hard_addr.clone();
        pair.virt_iface.hard_addr = "00:00:00:00:00:00".into();
        assert!(pair.del_network_model().await.is_err());
        assert!(get_link_by_name(&handle, tap).await.is_ok());
        pair.virt_iface.hard_addr = expected;
        pair.del_network_model().await.unwrap();
        assert!(get_link_by_name(&handle, tap).await.is_err());
        assert_eq!(
            get_link_by_name(&handle, peer).await.unwrap().attrs().index,
            peer_index
        );
    }
    handle.link().del(peer_index).execute().await.unwrap();
    worker.abort();
}
