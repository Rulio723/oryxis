//! Discovery panel + the per-result body that lists EC2 instances and
//! ECS services. The panel houses the title bar, search input, the
//! results list (split into EC2 / ECS sections), and the import action
//! footer. Already-imported entries are greyed out so the user
//! doesn't dupe them.

use iced::border::Radius;
use iced::widget::button::Status as BtnStatus;
use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{Background, Border, Color, Element, Length, Padding};

use crate::app::{CloudMessage, Message, Oryxis};
use crate::i18n::t;
use crate::state::CloudDiscoverState;
use crate::theme::OryxisColors;
use crate::widgets::{dir_align_x, dir_row};

use super::section_header;

impl Oryxis {
    pub(crate) fn view_cloud_discover_panel(&self) -> Element<'_, Message> {
        // Keyboard rows are recorded in visual order (row mode: Tab
        // walks everything, Up/Down hop between non-input rows).
        self.panel_nav_reset();
        // Header: title + refresh action + close (X), matching the
        // "title, actions, close" idiom of the host / group editor
        // panels. Both action glyphs are transparent muted icons (no
        // chip background) so this header reads identically to the
        // standard side-panel header.
        let header_icon_style = |_: &iced::Theme, _: BtnStatus| button::Style {
            background: Some(Background::Color(Color::TRANSPARENT)),
            border: Border::default(),
            ..Default::default()
        };
        let refresh_icon_btn: Element<'_, Message> = self.panel_nav_slot(
            crate::keynav::RowAction::activate(Message::Cloud(CloudMessage::CloudDiscoverRefresh)),
            4.0,
            button(
                iced_fonts::lucide::refresh_cw()
                    .size(15)
                    .color(OryxisColors::t().text_muted),
            )
            .on_press(Message::Cloud(CloudMessage::CloudDiscoverRefresh))
            .padding(Padding {
                top: 4.0,
                right: 8.0,
                bottom: 4.0,
                left: 8.0,
            })
            .style(header_icon_style)
            .into(),
        );
        // The close (X) is intentionally not a keyboard row: Esc
        // already owns panel close, and recording it would make the
        // header the first Down target instead of the results.
        let close_btn = button(text("\u{00D7}").size(20).color(OryxisColors::t().text_muted))
            .on_press(Message::Cloud(CloudMessage::HideCloudDiscover))
            .padding(Padding {
                top: 4.0,
                right: 8.0,
                bottom: 4.0,
                left: 8.0,
            })
            .style(header_icon_style);
        let title = container(
            dir_row(vec![
                text(t("cloud_discover"))
                    .size(16)
                    .color(OryxisColors::t().text_primary)
                    .into(),
                Space::new().width(Length::Fill).into(),
                refresh_icon_btn,
                Space::new().width(2).into(),
                close_btn.into(),
            ])
            .align_y(iced::Alignment::Center),
        )
        .padding(Padding {
            top: 12.0,
            right: 16.0,
            bottom: 12.0,
            left: 16.0,
        });

        // Search bar, only meaningful when results are loaded, but
        // we render it always so the panel layout doesn't shift when
        // the state transitions.
        // The panel surface is already `bg_surface`, so the shared
        // `rounded_input_style` (also `bg_surface`) would blend into it.
        // Lift the field one step to `bg_hover` so it reads as a raised
        // search field, exactly the relationship the toolbar search has
        // sitting on the darker main area.
        let search_input_style = |_: &iced::Theme, status: text_input::Status| {
            let c = OryxisColors::t();
            let (border_color, border_width) = match status {
                text_input::Status::Focused { .. } => (c.accent, 1.5),
                _ => (c.border, 1.0),
            };
            text_input::Style {
                background: Background::Color(c.bg_hover),
                border: Border {
                    radius: Radius::from(crate::widgets::INPUT_RADIUS),
                    width: border_width,
                    color: border_color,
                },
                placeholder: c.text_muted,
                value: c.text_primary,
                selection: c.accent,
            }
        };
        let search = container(
            self.panel_nav_slot(
                crate::keynav::RowAction::input(iced::widget::Id::new("panel-discover-search")),
                crate::widgets::INPUT_RADIUS,
                text_input(t("cloud_discover_search_ph"), &self.cloud_discover.filter)
                    .id(iced::widget::Id::new("panel-discover-search"))
                    .on_input(|v| Message::Cloud(CloudMessage::CloudDiscoverFilterChanged(v)))
                    .padding(Padding {
                        top: 9.0,
                        right: 12.0,
                        bottom: 9.0,
                        left: 12.0,
                    })
                    .size(13)
                    .style(search_input_style)
                    .align_x(dir_align_x())
                    .into(),
            ),
        )
        .padding(Padding {
            top: 0.0,
            right: 16.0,
            bottom: 12.0,
            left: 16.0,
        });

        // Body content varies by state, keep each branch self-
        // contained so the layout above stays readable.
        let body: Element<'_, Message> = match &self.cloud_discover.state {
            CloudDiscoverState::Idle => Space::new().into(),
            CloudDiscoverState::Running => container(
                text(t("cloud_discover_running"))
                    .size(13)
                    .color(OryxisColors::t().text_muted),
            )
            .center(Length::Fill)
            .into(),
            CloudDiscoverState::Failed(msg) => container(
                column![
                    text(format!("{}: {msg}", t("cloud_test_failed")))
                        .size(13)
                        .color(OryxisColors::t().error),
                    Space::new().height(12),
                    // Retry is a keyboard row: Enter re-runs discovery.
                    self.panel_nav_slot(
                        crate::keynav::RowAction::activate(Message::Cloud(CloudMessage::CloudDiscoverRefresh)),
                        6.0,
                        button(
                            container(
                                text(t("cloud_discover_refresh"))
                                    .size(12)
                                    .color(OryxisColors::t().text_primary),
                            )
                            .padding(Padding {
                                top: 6.0,
                                right: 12.0,
                                bottom: 6.0,
                                left: 12.0,
                            }),
                        )
                        .on_press(Message::Cloud(CloudMessage::CloudDiscoverRefresh))
                        .style(|_, _| button::Style {
                            background: Some(Background::Color(OryxisColors::t().bg_surface)),
                            border: Border {
                                radius: Radius::from(6.0),
                                color: OryxisColors::t().border,
                                width: 1.0,
                            },
                            ..Default::default()
                        })
                        .into(),
                    ),
                ]
                .align_x(iced::Alignment::Center),
            )
            .center(Length::Fill)
            .into(),
            CloudDiscoverState::Loaded(result) => self.view_discover_result_body(result),
        };

        // Footer: action buttons. Disabled / enabled depending on what
        // the current state allows. We re-render every frame so the
        // selection counter stays live.
        let import_count = self.cloud_discover.selected_ec2.len()
            + self.cloud_discover.selected_ecs.len()
            + self.cloud_discover.selected_k8s.len();
        let can_import = matches!(
            self.cloud_discover.state,
            CloudDiscoverState::Loaded(_)
        ) && import_count > 0;

        let import_btn = {
            let label = if import_count == 0 {
                t("cloud_discover_import_none").to_string()
            } else {
                format!("{} {import_count}", t("cloud_discover_import_n"))
            };
            let mut b = button(
                container(
                    text(label)
                        .size(13)
                        .color(OryxisColors::t().text_primary),
                )
                .padding(Padding {
                    top: 10.0,
                    right: 0.0,
                    bottom: 10.0,
                    left: 0.0,
                })
                .width(Length::Fill)
                .center_x(Length::Fill),
            )
            .width(Length::Fill)
            .style(move |_, _| button::Style {
                background: Some(Background::Color(if can_import {
                    OryxisColors::t().accent
                } else {
                    OryxisColors::t().bg_surface
                })),
                border: Border {
                    radius: Radius::from(8.0),
                    ..Default::default()
                },
                ..Default::default()
            });
            if can_import {
                b = b.on_press(Message::Cloud(CloudMessage::CloudDiscoverImport));
            }
            // Recorded only while actionable: ringing a disabled
            // Import would make Enter a silent no-op.
            if can_import {
                self.panel_nav_slot(
                    crate::keynav::RowAction::activate(Message::Cloud(CloudMessage::CloudDiscoverImport)),
                    8.0,
                    b.into(),
                )
            } else {
                Element::from(b)
            }
        };

        // Footer: just the Import button. Both target group and
        // transport selection now live inside the import-confirm
        // modal (one decision surface for the whole batch), so the
        // panel here stays focused on browsing + checking the
        // resources to bring in.
        let footer = column![import_btn];

        // Body wrapper keeps the leading + bottom insets but drops
        // the trailing padding: the scrollable inside
        // `view_discover_result_body` now owns its own right pad so
        // the scrollbar overlay lands in the panel's empty right
        // margin instead of overlapping the rows. Mirrors the host
        // editor / dynamic-group panel pattern.
        let panel_content = column![
            title,
            search,
            container(body).height(Length::Fill).padding(Padding {
                top: 0.0,
                right: 0.0,
                bottom: 8.0,
                left: 16.0,
            }),
            container(footer).padding(Padding {
                top: 0.0,
                right: 16.0,
                bottom: 16.0,
                left: 16.0,
            }),
        ]
        .height(Length::Fill);

        // Standardised side-panel chrome, matches the host
        // editor and the dynamic-group / wizard panels so the
        // right side of the dashboard reads as one consistent
        // surface regardless of which editor is open.
        crate::widgets::side_panel_frame(panel_content.into(), OryxisColors::t().bg_surface, self.panel_width)
    }

    /// Render the EC2 / ECS / K8s sections of the loaded discovery result.
    /// Already-imported resources are shown but disabled, the user can
    /// tell what's new at a glance.
    fn view_discover_result_body(
        &self,
        result: &oryxis_cloud::DiscoveryResult,
    ) -> Element<'_, Message> {
        if result.ec2.is_empty()
            && result.ecs_services.is_empty()
            && result.k8s_workloads.is_empty()
        {
            return container(
                text(t("cloud_discover_no_results"))
                    .size(13)
                    .color(OryxisColors::t().text_muted),
            )
            .center(Length::Fill)
            .into();
        }

        // Index of currently-imported (profile, instance_id) pairs so
        // we can grey out duplicates instead of letting the user
        // re-import them.
        let already: std::collections::HashSet<String> = self
            .connections
            .iter()
            .filter_map(|c| {
                let cr = c.cloud_ref.as_ref()?;
                if Some(cr.profile_id) == self.cloud_discover.profile_id {
                    Some(cr.resource_id.clone())
                } else {
                    None
                }
            })
            .collect();

        // Apply the live filter, case-insensitive substring match
        // across name, instance-id, region, public/private DNS+IP.
        // The total count above the section reflects unfiltered size
        // so the user sees how much got hidden vs. the raw discovery
        // total.
        let needle = self.cloud_discover.filter.trim().to_lowercase();
        let matches_filter = |e: &oryxis_cloud::DiscoveredEc2| -> bool {
            if needle.is_empty() {
                return true;
            }
            let mut hay = String::new();
            if let Some(n) = &e.name { hay.push_str(n); hay.push(' '); }
            hay.push_str(&e.instance_id);
            hay.push(' ');
            hay.push_str(&e.region);
            for v in [&e.public_dns, &e.public_ip, &e.private_dns, &e.private_ip]
                .iter()
                .copied()
                .flatten()
            {
                hay.push(' ');
                hay.push_str(v);
            }
            hay.to_lowercase().contains(&needle)
        };

        // Group EC2 by region so the user sees the cloud's natural
        // boundary instead of an undifferentiated flat list.
        let mut by_region: std::collections::BTreeMap<String, Vec<&oryxis_cloud::DiscoveredEc2>> =
            std::collections::BTreeMap::new();
        let mut filtered_count = 0usize;
        for e in &result.ec2 {
            if matches_filter(e) {
                by_region.entry(e.region.clone()).or_default().push(e);
                filtered_count += 1;
            }
        }

        let mut sections: Vec<Element<'_, Message>> = Vec::new();
        // Hide the EC2 section entirely when zero entries match
        // showing an empty header reads as broken / loading. Same
        // policy applies to ECS below. The "no matches" hint at the
        // very bottom catches the case where every section is empty.
        let ec2_collapsed = self.cloud_discover.collapsed.contains("ec2");
        let show_ec2_section = filtered_count > 0;
        if show_ec2_section {
            // Provider-aware section title: the VM family is "EC2" on AWS
            // but "Instances" (Compute Engine) on GCP, both flow through
            // the shared `result.ec2`. Resolve from the profile being
            // discovered; default to the generic "Instances".
            let vm_label = match self
                .cloud_discover.profile_id
                .and_then(|id| self.cloud_profiles.iter().find(|p| p.id == id))
                .map(|p| p.provider.as_str())
            {
                Some("aws") => "EC2",
                _ => "Instances",
            };
            let header_text = if needle.is_empty() {
                format!("{vm_label} ({})", result.ec2.len())
            } else {
                format!("{vm_label} ({} / {})", filtered_count, result.ec2.len())
            };
            // Collapsible headers are keyboard rows too, so the whole
            // checklist can be driven without the mouse.
            sections.push(self.panel_nav_slot(
                crate::keynav::RowAction::activate(Message::Cloud(CloudMessage::CloudDiscoverToggleSection(
                    "ec2".to_string(),
                ))),
                4.0,
                section_header("ec2", &header_text, ec2_collapsed),
            ));
            sections.push(Space::new().height(6).into());
        }

        if !show_ec2_section || ec2_collapsed {
            // Skip rendering EC2 rows entirely, header alone wraps
            // the section, the rest of the panel reflows to give the
            // collapsed state real space-saving value.
        } else {
        for (region, items) in by_region {
            sections.push(
                text(format!("📍 {region}"))
                    .size(11)
                    .color(OryxisColors::t().text_muted)
                    .into(),
            );
            sections.push(Space::new().height(4).into());
            for e in items {
                let is_imported = already.contains(&e.instance_id);
                let checked = self.cloud_discover.selected_ec2.contains(&e.instance_id);
                let id_for_msg = e.instance_id.clone();
                let label_text = match (&e.name, e.public_dns.as_deref().or(e.public_ip.as_deref()))
                {
                    (Some(name), Some(addr)) => format!("{name}  ({})  {addr}", e.instance_id),
                    (Some(name), None) => format!("{name}  ({})", e.instance_id),
                    (None, Some(addr)) => format!("{}  {addr}", e.instance_id),
                    (None, None) => e.instance_id.clone(),
                };
                let label_text = if is_imported {
                    format!("{label_text}  ·  {}", t("cloud_discover_already_imported"))
                } else {
                    label_text
                };
                let row_el: Element<'_, Message> = if is_imported {
                    text(label_text)
                        .size(11)
                        .color(OryxisColors::t().text_muted)
                        .into()
                } else {
                    let mark = if checked {
                        iced_fonts::lucide::circle_check()
                            .size(13)
                            .color(OryxisColors::t().accent)
                    } else {
                        iced_fonts::lucide::circle_minus()
                            .size(13)
                            .color(OryxisColors::t().text_muted)
                    };
                    // Checkbox toggle is the keyboard row (Enter/Space
                    // flip it, selection stays for repeat toggling).
                    self.panel_nav_slot(
                        crate::keynav::RowAction::activate(Message::Cloud(CloudMessage::CloudDiscoverToggleEc2(
                            id_for_msg.clone(),
                        ))),
                        4.0,
                        button(
                            row![
                                mark,
                                Space::new().width(8),
                                text(label_text)
                                    .size(11)
                                    .color(OryxisColors::t().text_secondary),
                            ]
                            .align_y(iced::Alignment::Center),
                        )
                        .on_press(Message::Cloud(CloudMessage::CloudDiscoverToggleEc2(id_for_msg)))
                        .padding(Padding {
                            top: 3.0,
                            right: 6.0,
                            bottom: 3.0,
                            left: 4.0,
                        })
                        .style(|_, status| {
                            let bg = match status {
                                BtnStatus::Hovered => OryxisColors::t().bg_hover,
                                _ => Color::TRANSPARENT,
                            };
                            button::Style {
                                background: Some(Background::Color(bg)),
                                border: Border {
                                    radius: Radius::from(4.0),
                                    ..Default::default()
                                },
                                ..Default::default()
                            }
                        })
                        .into(),
                    )
                };
                sections.push(row_el);
                sections.push(Space::new().height(2).into());
            }
            sections.push(Space::new().height(8).into());
        }
        } // end `if !ec2_collapsed` block

        // ── ECS section ──
        // ECS services are imported as *dynamic groups* (one per
        // service+container) rather than individual hosts, since
        // task IDs are ephemeral. Already-imported services greyed
        // out so the user doesn't dupe them.
        let already_ecs: std::collections::HashSet<String> = self
            .groups
            .iter()
            .filter_map(|g| {
                let q = g.cloud_query.as_ref()?;
                if q.profile_id != self.cloud_discover.profile_id? {
                    return None;
                }
                match &q.kind {
                    oryxis_core::models::cloud::CloudQueryKind::EcsTasks {
                        cluster,
                        service,
                        container,
                    } => Some(format!("{cluster}/{service}/{container}")),
                    _ => None,
                }
            })
            .collect();

        let ecs_match_filter = |s: &oryxis_cloud::DiscoveredEcsService| -> bool {
            if needle.is_empty() {
                return true;
            }
            let hay = format!(
                "{} {} {} {}",
                s.cluster, s.service, s.container, s.region
            )
            .to_lowercase();
            hay.contains(&needle)
        };

        let ecs_filtered: Vec<&oryxis_cloud::DiscoveredEcsService> = result
            .ecs_services
            .iter()
            .filter(|s| ecs_match_filter(s))
            .collect();

        // Same auto-hide policy as EC2: only emit the ECS section if
        // there's at least one entry surviving the filter.
        if !ecs_filtered.is_empty() {
            sections.push(Space::new().height(8).into());
            let ecs_header = if needle.is_empty() {
                format!("ECS Services ({})", result.ecs_services.len())
            } else {
                format!(
                    "ECS Services ({} / {})",
                    ecs_filtered.len(),
                    result.ecs_services.len()
                )
            };
            let ecs_collapsed = self.cloud_discover.collapsed.contains("ecs");
            sections.push(self.panel_nav_slot(
                crate::keynav::RowAction::activate(Message::Cloud(CloudMessage::CloudDiscoverToggleSection(
                    "ecs".to_string(),
                ))),
                4.0,
                section_header("ecs", &ecs_header, ecs_collapsed),
            ));
            sections.push(Space::new().height(6).into());

            if ecs_collapsed {
                // collapsed, skip body
            } else {

            // Group by region → cluster so the user reads
            // `📍 region / 🗂 cluster` then services. Tasks are
            // ephemeral; the import unit is the (service, container)
            // pair, which becomes a dynamic Group.
            let mut by_region_cluster: std::collections::BTreeMap<
                (String, String),
                Vec<&oryxis_cloud::DiscoveredEcsService>,
            > = std::collections::BTreeMap::new();
            for s in &ecs_filtered {
                by_region_cluster
                    .entry((s.region.clone(), s.cluster.clone()))
                    .or_default()
                    .push(s);
            }

            for ((region, cluster), items) in by_region_cluster {
                sections.push(
                    text(format!("📍 {region}  ·  {cluster}"))
                        .size(11)
                        .color(OryxisColors::t().text_muted)
                        .into(),
                );
                sections.push(Space::new().height(4).into());
                for s in items {
                    let key = format!("{}/{}/{}", s.cluster, s.service, s.container);
                    let is_imported = already_ecs.contains(&key);
                    let checked = self.cloud_discover.selected_ecs.contains(&key);
                    let label_text = format!(
                        "{} / {}  ·  {} {}",
                        s.service,
                        s.container,
                        s.running_task_count,
                        t("cloud_discover_tasks_unit")
                    );
                    let label_text = if is_imported {
                        format!("{label_text}  ·  {}", t("cloud_discover_already_imported"))
                    } else {
                        label_text
                    };
                    let row_el: Element<'_, Message> = if is_imported {
                        text(label_text)
                            .size(11)
                            .color(OryxisColors::t().text_muted)
                            .into()
                    } else {
                        let mark = if checked {
                            iced_fonts::lucide::circle_check()
                                .size(13)
                                .color(OryxisColors::t().accent)
                        } else {
                            iced_fonts::lucide::circle_minus()
                                .size(13)
                                .color(OryxisColors::t().text_muted)
                        };
                        let key_for_msg = key.clone();
                        // Checkbox toggle is the keyboard row.
                        self.panel_nav_slot(
                            crate::keynav::RowAction::activate(
                                Message::Cloud(CloudMessage::CloudDiscoverToggleEcs(key.clone())),
                            ),
                            4.0,
                            button(
                                row![
                                    mark,
                                    Space::new().width(8),
                                    text(label_text)
                                        .size(11)
                                        .color(OryxisColors::t().text_secondary),
                                ]
                                .align_y(iced::Alignment::Center),
                            )
                            .on_press(Message::Cloud(CloudMessage::CloudDiscoverToggleEcs(key_for_msg)))
                            .padding(Padding {
                                top: 3.0,
                                right: 6.0,
                                bottom: 3.0,
                                left: 4.0,
                            })
                            .style(|_, status| {
                                let bg = match status {
                                    BtnStatus::Hovered => OryxisColors::t().bg_hover,
                                    _ => Color::TRANSPARENT,
                                };
                                button::Style {
                                    background: Some(Background::Color(bg)),
                                    border: Border {
                                        radius: Radius::from(4.0),
                                        ..Default::default()
                                    },
                                    ..Default::default()
                                }
                            })
                            .into(),
                        )
                    };
                    sections.push(row_el);
                    sections.push(Space::new().height(2).into());
                }
                sections.push(Space::new().height(8).into());
            }
            } // end `if !ecs_collapsed` block
        }

        // ── Kubernetes workloads ── each surviving workload becomes a
        // dynamic Group backed by a `K8sPods` label query.
        let labels_key = |labels: &std::collections::BTreeMap<String, String>| -> String {
            labels
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        // Already-imported workloads: groups carrying a `K8sPods` query
        // for this profile, keyed by `namespace|labels` so a re-discovery
        // greys them out instead of offering a duplicate import.
        let already_k8s: std::collections::HashSet<String> = self
            .groups
            .iter()
            .filter_map(|g| {
                let q = g.cloud_query.as_ref()?;
                if Some(q.profile_id) != self.cloud_discover.profile_id {
                    return None;
                }
                if let oryxis_core::models::cloud::CloudQueryKind::K8sPods {
                    namespace,
                    selector: oryxis_core::models::cloud::PodSelector::Labels(m),
                    ..
                } = &q.kind
                {
                    Some(format!("{namespace}|{}", labels_key(m)))
                } else {
                    None
                }
            })
            .collect();

        let k8s_match_filter = |w: &oryxis_cloud::DiscoveredK8sWorkload| -> bool {
            if needle.is_empty() {
                return true;
            }
            format!("{} {} {} {}", w.namespace, w.kind, w.name, w.container)
                .to_lowercase()
                .contains(&needle)
        };
        let k8s_filtered: Vec<&oryxis_cloud::DiscoveredK8sWorkload> = result
            .k8s_workloads
            .iter()
            .filter(|w| k8s_match_filter(w))
            .collect();

        if !k8s_filtered.is_empty() {
            sections.push(Space::new().height(8).into());
            let k8s_header = if needle.is_empty() {
                format!("{} ({})", t("cloud_k8s_workloads"), result.k8s_workloads.len())
            } else {
                format!(
                    "{} ({} / {})",
                    t("cloud_k8s_workloads"),
                    k8s_filtered.len(),
                    result.k8s_workloads.len()
                )
            };
            let k8s_collapsed = self.cloud_discover.collapsed.contains("k8s");
            sections.push(self.panel_nav_slot(
                crate::keynav::RowAction::activate(Message::Cloud(CloudMessage::CloudDiscoverToggleSection(
                    "k8s".to_string(),
                ))),
                4.0,
                section_header("k8s", &k8s_header, k8s_collapsed),
            ));
            sections.push(Space::new().height(6).into());

            if !k8s_collapsed {
                // Group by namespace so the user reads `▸ namespace` then
                // its workloads.
                let mut by_ns: std::collections::BTreeMap<
                    String,
                    Vec<&oryxis_cloud::DiscoveredK8sWorkload>,
                > = std::collections::BTreeMap::new();
                for w in &k8s_filtered {
                    by_ns.entry(w.namespace.clone()).or_default().push(w);
                }
                for (namespace, items) in by_ns {
                    sections.push(
                        text(format!("\u{25B8} {namespace}"))
                            .size(11)
                            .color(OryxisColors::t().text_muted)
                            .into(),
                    );
                    sections.push(Space::new().height(4).into());
                    for w in items {
                        // Selection key: workload identity. Import looks the
                        // workload back up by this same triple.
                        let key = format!("{}/{}/{}", w.namespace, w.kind, w.name);
                        let imported_key = format!("{}|{}", w.namespace, labels_key(&w.match_labels));
                        let is_imported = already_k8s.contains(&imported_key);
                        let checked = self.cloud_discover.selected_k8s.contains(&key);
                        let mut label_text = format!(
                            "{} {}  ·  {} pod(s)",
                            w.kind, w.name, w.running_pod_count
                        );
                        if is_imported {
                            label_text =
                                format!("{label_text}  ·  {}", t("cloud_discover_already_imported"));
                        }
                        let row_el: Element<'_, Message> = if is_imported {
                            text(label_text)
                                .size(11)
                                .color(OryxisColors::t().text_muted)
                                .into()
                        } else {
                            let mark = if checked {
                                iced_fonts::lucide::circle_check()
                                    .size(13)
                                    .color(OryxisColors::t().accent)
                            } else {
                                iced_fonts::lucide::circle_minus()
                                    .size(13)
                                    .color(OryxisColors::t().text_muted)
                            };
                            let key_for_msg = key.clone();
                            // Checkbox toggle is the keyboard row.
                            self.panel_nav_slot(
                                crate::keynav::RowAction::activate(
                                    Message::Cloud(CloudMessage::CloudDiscoverToggleK8s(key.clone())),
                                ),
                                4.0,
                                button(
                                    row![
                                        mark,
                                        Space::new().width(8),
                                        text(label_text)
                                            .size(11)
                                            .color(OryxisColors::t().text_secondary),
                                    ]
                                    .align_y(iced::Alignment::Center),
                                )
                                .on_press(Message::Cloud(CloudMessage::CloudDiscoverToggleK8s(key_for_msg)))
                                .padding(Padding {
                                    top: 3.0,
                                    right: 6.0,
                                    bottom: 3.0,
                                    left: 4.0,
                                })
                                .style(|_, status| {
                                    let bg = match status {
                                        BtnStatus::Hovered => OryxisColors::t().bg_hover,
                                        _ => Color::TRANSPARENT,
                                    };
                                    button::Style {
                                        background: Some(Background::Color(bg)),
                                        border: Border {
                                            radius: Radius::from(4.0),
                                            ..Default::default()
                                        },
                                        ..Default::default()
                                    }
                                })
                                .into(),
                            )
                        };
                        sections.push(row_el);
                        sections.push(Space::new().height(2).into());
                    }
                    sections.push(Space::new().height(8).into());
                }
            }
        }

        // GKE clusters: not batch-imported like the checklists above.
        // Each cluster is "added" individually, which fetches its
        // kubeconfig (get-credentials) and creates a Kubernetes account
        // pointed at it, after which the user discovers workloads there.
        let gke_filtered: Vec<&oryxis_cloud::DiscoveredGkeCluster> = result
            .gke_clusters
            .iter()
            .filter(|c| {
                needle.is_empty()
                    || format!("{} {} {}", c.name, c.location, c.status)
                        .to_lowercase()
                        .contains(&needle)
            })
            .collect();
        if !gke_filtered.is_empty() {
            // Dup-guard: a k8s profile already pointed at a cluster's
            // context means it's been added; show it greyed instead of
            // minting a duplicate on a second Add.
            let existing_contexts: std::collections::HashSet<String> = self
                .cloud_profiles
                .iter()
                .filter(|p| p.provider == "k8s")
                .filter_map(|p| {
                    serde_json::from_str::<serde_json::Value>(&p.config)
                        .ok()?
                        .get("context")?
                        .as_str()
                        .map(str::to_string)
                })
                .collect();
            sections.push(Space::new().height(8).into());
            let gke_header = if needle.is_empty() {
                format!("{} ({})", t("cloud_gke_clusters"), result.gke_clusters.len())
            } else {
                format!(
                    "{} ({} / {})",
                    t("cloud_gke_clusters"),
                    gke_filtered.len(),
                    result.gke_clusters.len()
                )
            };
            let gke_collapsed = self.cloud_discover.collapsed.contains("gke");
            sections.push(self.panel_nav_slot(
                crate::keynav::RowAction::activate(Message::Cloud(CloudMessage::CloudDiscoverToggleSection(
                    "gke".to_string(),
                ))),
                4.0,
                section_header("gke", &gke_header, gke_collapsed),
            ));
            sections.push(Space::new().height(6).into());
            if !gke_collapsed {
                for c in &gke_filtered {
                    let added = existing_contexts.contains(&c.context);
                    let info = format!(
                        "{}  ·  {}  ·  {} {}  ·  {}",
                        c.name,
                        c.location,
                        c.node_count,
                        t("cloud_discover_nodes_unit"),
                        c.status
                    );
                    let row_el: Element<'_, Message> = if added {
                        text(format!("{info}  ·  {}", t("cloud_discover_already_imported")))
                            .size(11)
                            .color(OryxisColors::t().text_muted)
                            .into()
                    } else {
                        let add_msg = Message::Cloud(CloudMessage::CloudDiscoverAddGke {
                            cluster: c.name.clone(),
                            location: c.location.clone(),
                        });
                        dir_row(vec![
                            text(info)
                                .size(11)
                                .color(OryxisColors::t().text_secondary)
                                .width(Length::Fill)
                                .into(),
                            self.panel_nav_slot(
                                crate::keynav::RowAction::activate(add_msg.clone()),
                                4.0,
                                button(
                                    text(t("cloud_gke_add"))
                                        .size(11)
                                        .color(OryxisColors::t().text_primary),
                                )
                                .on_press(add_msg)
                                .padding(Padding { top: 3.0, right: 10.0, bottom: 3.0, left: 10.0 })
                                .style(|_, status| {
                                    let bg = match status {
                                        BtnStatus::Hovered | BtnStatus::Pressed => {
                                            OryxisColors::t().bg_hover
                                        }
                                        _ => OryxisColors::t().bg_surface,
                                    };
                                    button::Style {
                                        background: Some(Background::Color(bg)),
                                        border: Border {
                                            radius: Radius::from(4.0),
                                            width: 1.0,
                                            color: OryxisColors::t().border,
                                        },
                                        ..Default::default()
                                    }
                                })
                                .into(),
                            ),
                        ])
                        .align_y(iced::Alignment::Center)
                        .into()
                    };
                    sections.push(row_el);
                    sections.push(Space::new().height(2).into());
                }
                sections.push(Space::new().height(8).into());
            }
        }

        // AKS clusters: same individual-add flow as GKE (get-credentials
        // then a Kubernetes account), keyed by resource group instead of
        // region.
        let aks_filtered: Vec<&oryxis_cloud::DiscoveredAksCluster> = result
            .aks_clusters
            .iter()
            .filter(|c| {
                needle.is_empty()
                    || format!("{} {} {} {}", c.name, c.resource_group, c.location, c.status)
                        .to_lowercase()
                        .contains(&needle)
            })
            .collect();
        if !aks_filtered.is_empty() {
            // Dup-guard: a k8s profile already pointed at a cluster's
            // context means it's been added; show it greyed instead of
            // minting a duplicate on a second Add.
            let existing_contexts: std::collections::HashSet<String> = self
                .cloud_profiles
                .iter()
                .filter(|p| p.provider == "k8s")
                .filter_map(|p| {
                    serde_json::from_str::<serde_json::Value>(&p.config)
                        .ok()?
                        .get("context")?
                        .as_str()
                        .map(str::to_string)
                })
                .collect();
            sections.push(Space::new().height(8).into());
            let aks_header = if needle.is_empty() {
                format!("{} ({})", t("cloud_aks_clusters"), result.aks_clusters.len())
            } else {
                format!(
                    "{} ({} / {})",
                    t("cloud_aks_clusters"),
                    aks_filtered.len(),
                    result.aks_clusters.len()
                )
            };
            let aks_collapsed = self.cloud_discover.collapsed.contains("aks");
            sections.push(self.panel_nav_slot(
                crate::keynav::RowAction::activate(Message::Cloud(CloudMessage::CloudDiscoverToggleSection(
                    "aks".to_string(),
                ))),
                4.0,
                section_header("aks", &aks_header, aks_collapsed),
            ));
            sections.push(Space::new().height(6).into());
            if !aks_collapsed {
                for c in &aks_filtered {
                    // Match the composite `<cluster>-<resource_group>`
                    // context this build mints, or the bare cluster name
                    // older builds stored (az's default context name), so
                    // a legacy import is still recognized as added.
                    let added = existing_contexts.contains(&c.context)
                        || existing_contexts.contains(&c.name);
                    let info = format!(
                        "{}  ·  {}  ·  {}  ·  {} {}  ·  {}",
                        c.name,
                        c.resource_group,
                        c.location,
                        c.node_count,
                        t("cloud_discover_nodes_unit"),
                        c.status
                    );
                    let row_el: Element<'_, Message> = if added {
                        text(format!("{info}  ·  {}", t("cloud_discover_already_imported")))
                            .size(11)
                            .color(OryxisColors::t().text_muted)
                            .into()
                    } else {
                        let add_msg = Message::Cloud(CloudMessage::CloudDiscoverAddAks {
                            cluster: c.name.clone(),
                            resource_group: c.resource_group.clone(),
                        });
                        dir_row(vec![
                            text(info)
                                .size(11)
                                .color(OryxisColors::t().text_secondary)
                                .width(Length::Fill)
                                .into(),
                            self.panel_nav_slot(
                                crate::keynav::RowAction::activate(add_msg.clone()),
                                4.0,
                                button(
                                    text(t("cloud_aks_add"))
                                        .size(11)
                                        .color(OryxisColors::t().text_primary),
                                )
                                .on_press(add_msg)
                                .padding(Padding { top: 3.0, right: 10.0, bottom: 3.0, left: 10.0 })
                                .style(|_, status| {
                                    let bg = match status {
                                        BtnStatus::Hovered | BtnStatus::Pressed => {
                                            OryxisColors::t().bg_hover
                                        }
                                        _ => OryxisColors::t().bg_surface,
                                    };
                                    button::Style {
                                        background: Some(Background::Color(bg)),
                                        border: Border {
                                            radius: Radius::from(4.0),
                                            width: 1.0,
                                            color: OryxisColors::t().border,
                                        },
                                        ..Default::default()
                                    }
                                })
                                .into(),
                            ),
                        ])
                        .align_y(iced::Alignment::Center)
                        .into()
                    };
                    sections.push(row_el);
                    sections.push(Space::new().height(2).into());
                }
                sections.push(Space::new().height(8).into());
            }
        }

        // ACK / TKE clusters: the providers whose API returns the
        // kubeconfig instead of writing it. One section per family, in
        // the order the result lists them; each cluster is added
        // individually, which writes its kubeconfig to a file of its own
        // and creates a Kubernetes account pointed at it. An added
        // cluster keeps its button as a refresh: the ACK credential is
        // temporary, so the file has to be re-fetchable from here.
        let managed_filtered: Vec<&oryxis_cloud::DiscoveredManagedCluster> = result
            .managed_clusters
            .iter()
            .filter(|c| {
                needle.is_empty()
                    || format!("{} {} {} {}", c.name, c.id, c.region, c.status)
                        .to_lowercase()
                        .contains(&needle)
            })
            .collect();
        if !managed_filtered.is_empty() {
            // Dup-guard by the kubeconfig FILE a k8s profile points at,
            // which is deterministic per (family, cluster id, cloud
            // account): no context name has to be known before the fetch.
            let existing_kubeconfigs: std::collections::HashSet<String> = self
                .cloud_profiles
                .iter()
                .filter(|p| p.provider == "k8s")
                .filter_map(|p| {
                    serde_json::from_str::<serde_json::Value>(&p.config)
                        .ok()?
                        .get("kubeconfig")?
                        .as_str()
                        .map(str::to_string)
                })
                .collect();
            let mut families: Vec<&str> = Vec::new();
            for c in &managed_filtered {
                if !families.contains(&c.family.as_str()) {
                    families.push(&c.family);
                }
            }
            for family in families {
                let rows: Vec<&&oryxis_cloud::DiscoveredManagedCluster> =
                    managed_filtered.iter().filter(|c| c.family == family).collect();
                let total = result
                    .managed_clusters
                    .iter()
                    .filter(|c| c.family == family)
                    .count();
                // A family this build does not know (a newer plugin) is
                // named verbatim rather than hidden.
                let title: String = match family {
                    "ack" => t("cloud_ack_clusters").to_string(),
                    "tke" => t("cloud_tke_clusters").to_string(),
                    other => other.to_uppercase(),
                };
                sections.push(Space::new().height(8).into());
                let header = if needle.is_empty() {
                    format!("{title} ({total})")
                } else {
                    format!("{title} ({} / {total})", rows.len())
                };
                // The collapse key is static like the other sections'
                // (`section_header` wants a `'static` id); an unknown
                // family shares one key rather than growing a new one.
                let section_key: &'static str = match family {
                    "ack" => "ack",
                    "tke" => "tke",
                    _ => "managed",
                };
                let collapsed = self.cloud_discover.collapsed.contains(section_key);
                sections.push(self.panel_nav_slot(
                    crate::keynav::RowAction::activate(Message::Cloud(
                        CloudMessage::CloudDiscoverToggleSection(section_key.to_string()),
                    )),
                    4.0,
                    section_header(section_key, &header, collapsed),
                ));
                sections.push(Space::new().height(6).into());
                if collapsed {
                    continue;
                }
                let account = self.cloud_discover.profile_id.unwrap_or_default();
                for c in rows {
                    // Added = an account points at this (cluster, account)
                    // file. Another cloud account's file for the same
                    // cluster does not count: it is a different credential.
                    let path = crate::kubeconfig_file::path_for(&c.family, account, &c.id).ok();
                    let added = path
                        .as_ref()
                        .is_some_and(|p| existing_kubeconfigs.contains(&p.to_string_lossy().into_owned()));
                    let fetching = path
                        .as_ref()
                        .is_some_and(|p| self.cloud_discover.managed_in_flight.contains(p));
                    let mut info = format!("{}  ·  {}", c.name, c.region);
                    if !c.version.trim().is_empty() {
                        info.push_str(&format!("  ·  {}", c.version));
                    }
                    info.push_str(&format!(
                        "  ·  {} {}  ·  {}",
                        c.node_count,
                        t("cloud_discover_nodes_unit"),
                        c.status
                    ));
                    if added {
                        info.push_str(&format!("  ·  {}", t("cloud_discover_already_imported")));
                    }
                    let add_msg = Message::Cloud(CloudMessage::CloudDiscoverAddManagedCluster {
                        family: c.family.clone(),
                        id: c.id.clone(),
                        name: c.name.clone(),
                    });
                    let button_label = if fetching {
                        t("cloud_managed_cluster_fetching")
                    } else if added {
                        t("cloud_managed_cluster_refresh")
                    } else {
                        t("cloud_managed_cluster_add")
                    };
                    let info_color = if added {
                        OryxisColors::t().text_muted
                    } else {
                        OryxisColors::t().text_secondary
                    };
                    let row_el: Element<'_, Message> = dir_row(vec![
                        text(info)
                            .size(11)
                            .color(info_color)
                            .width(Length::Fill)
                            .into(),
                        self.panel_nav_slot(
                            crate::keynav::RowAction::activate(add_msg.clone()),
                            4.0,
                            button(
                                text(button_label)
                                    .size(11)
                                    .color(OryxisColors::t().text_primary),
                            )
                            // Disabled while the fetch runs, so a second
                            // click cannot race the first one's file.
                            .on_press_maybe((!fetching).then_some(add_msg))
                            .padding(Padding { top: 3.0, right: 10.0, bottom: 3.0, left: 10.0 })
                            .style(|_, status| {
                                let bg = match status {
                                    BtnStatus::Hovered | BtnStatus::Pressed => {
                                        OryxisColors::t().bg_hover
                                    }
                                    BtnStatus::Disabled => OryxisColors::t().bg_primary,
                                    _ => OryxisColors::t().bg_surface,
                                };
                                button::Style {
                                    background: Some(Background::Color(bg)),
                                    border: Border {
                                        radius: Radius::from(4.0),
                                        width: 1.0,
                                        color: OryxisColors::t().border,
                                    },
                                    ..Default::default()
                                }
                            })
                            .into(),
                        ),
                    ])
                    .align_y(iced::Alignment::Center)
                    .into();
                    sections.push(row_el);
                    sections.push(Space::new().height(2).into());
                }
                sections.push(Space::new().height(8).into());
            }
        }

        // Every section hid itself under the active filter, show
        // a friendly hint instead of an empty scroll area so the
        // panel doesn't read as "broken".
        if !show_ec2_section
            && ecs_filtered.is_empty()
            && k8s_filtered.is_empty()
            && gke_filtered.is_empty()
            && aks_filtered.is_empty()
            && managed_filtered.is_empty()
            && !needle.is_empty()
        {
            sections.push(
                container(
                    text(t("cloud_discover_no_matches"))
                        .size(12)
                        .color(OryxisColors::t().text_muted),
                )
                .center_x(Length::Fill)
                .padding(Padding {
                    top: 24.0,
                    right: 0.0,
                    bottom: 0.0,
                    left: 0.0,
                })
                .into(),
            );
        }

        // Right padding pushes the rows away from the scrollbar
        // overlay; the outer panel container intentionally dropped
        // its trailing pad so the scrollbar can sit in the empty
        // right margin instead of biting into row content.
        scrollable(
            column(sections).padding(Padding {
                top: 0.0,
                right: 20.0,
                bottom: 0.0,
                left: 0.0,
            }),
        )
        // Shared id: the keyboard router keeps the selected row in view.
        .id(iced::widget::Id::new("side-panel-scroll"))
        .height(Length::Fill)
        .into()
    }
}
