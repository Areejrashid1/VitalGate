# VitalGate test-bed evaluation

Frozen bundle 2026-11-14 19:20:18 | 66 pcaps | 6,801 windows | 21.6 host-hours | 43 attack runs (0 not seen by the sensor)
## Detection and response
| policy | contained | runs | median_TTC_s | benign_min_restricted_per_h | clinical_min_blocked_per_h | false_actions_per_h |
|---|---|---|---|---|---|---|
| ladder | 31 | 43 | 3.8 | 0.2753 | 0.0 | 0.2784 |
| binary | 31 | 43 | 3.8 | 0.1655 | 0.0418 | 0.2784 |

Detected 31/43 runs, median time to detect 3.8 s (from the attack's real start), false alarm episodes 0.3248 per host-hour.

## Known vs novel techniques
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| known | 15 | 12 | [52, 96] | 12 | 3.8 | 3.75 | 0.784 |
| novel | 28 | 19 | [48, 84] | 19 | 4.0 | 4.0 | 0.836 |

## By class
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce | 5 | 5 | [48, 100] | 5 | 5.8 | 5.8 | 1.0 |
| assoc_flood | 5 | 0 | [0, 52] | 0 |  |  |  |
| exfiltration | 8 | 6 | [35, 97] | 6 | 50.2 | 40.4 | 0.934 |
| malformed_pdu | 6 | 2 | [4, 78] | 2 | 4.4 | 4.4 | 0.049 |
| preamble_polyglot | 7 | 7 | [59, 100] | 7 | 0.5 | 0.5 | 0.956 |
| ransomware_like | 4 | 4 | [40, 100] | 4 | 4.45 | 4.45 | 0.732 |
| recon | 8 | 7 | [47, 100] | 7 | 4.0 | 4.0 | 0.71 |

## By variant
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce/echo_guess | 2 | 2 | [16, 100] | 2 | 11.05 | 11.05 | 1.0 |
| ae_bruteforce/find_guess (novel) | 3 | 3 | [29, 100] | 3 | 3.5 | 3.5 | 1.0 |
| assoc_flood/echo_storm (novel) | 3 | 0 | [0, 71] | 0 |  |  |  |
| assoc_flood/hold_full_rq | 2 | 0 | [0, 84] | 0 |  |  |  |
| exfiltration/drip (novel) | 3 | 1 | [1, 91] | 1 | 27.2 | 27.2 | 1.0 |
| exfiltration/find_get | 2 | 2 | [16, 100] | 2 | 25.299999999999997 | 2.3 | 0.972 |
| exfiltration/move_to_self (novel) | 3 | 3 | [29, 100] | 3 | 70.1 | 70.1 | 0.887 |
| malformed_pdu/assoc_fuzz | 3 | 2 | [9, 99] | 2 | 4.4 | 4.4 | 0.049 |
| malformed_pdu/pdata_fuzz (novel) | 3 | 0 | [0, 71] | 0 |  |  |  |
| preamble_polyglot/rest_elf (novel) | 2 | 2 | [16, 100] | 2 | 0.75 | 0.75 | 0.982 |
| preamble_polyglot/rest_mz | 2 | 2 | [16, 100] | 2 | 0.65 | 0.65 | 0.985 |
| preamble_polyglot/stow_mz (novel) | 3 | 3 | [29, 100] | 3 | 0.5 | 0.5 | 0.92 |
| ransomware_like/get_restore | 2 | 2 | [16, 100] | 2 | 4.05 | 4.05 | 0.714 |
| ransomware_like/get_restore_delete (novel) | 2 | 2 | [16, 100] | 2 | 5.35 | 5.35 | 0.75 |
| recon/dicom_ping (novel) | 3 | 2 | [9, 99] | 2 | 25.05 | 25.05 | 0.0 |
| recon/nmap_connect | 2 | 2 | [16, 100] | 2 | 3.5 | 3.5 | 0.984 |
| recon/nmap_syn (novel) | 3 | 3 | [29, 100] | 3 | 4.0 | 4.0 | 1.0 |

## By intensity
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| high | 16 | 12 | [48, 93] | 12 | 4.75 | 4.15 | 0.712 |
| low | 14 | 10 | [42, 92] | 10 | 3.9 | 3.9 | 0.877 |
| slow | 13 | 9 | [39, 91] | 9 | 3.3 | 3.3 | 0.886 |

## By attack source
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| modality | 9 | 5 | [21, 86] | 5 | 5.8 | 5.8 | 0.381 |
| unknown | 22 | 17 | [55, 92] | 17 | 3.3 | 3.3 | 0.883 |
| workstation | 12 | 9 | [43, 95] | 9 | 31.5 | 16.3 | 0.932 |

## Benign hosts
| host | role | windows | flagged_share | alarm_windows | max_level |
|---|---|---|---|---|---|
| 172.28.1.31 | modality | 297 | 0.1178 | 7 | 3 |
| 172.28.1.32 | modality | 170 | 0.0706 | 3 | 2 |
| 172.28.1.33 | modality | 304 | 0.3618 | 0 | 0 |
| 172.28.1.34 | modality | 358 | 0.148 | 3 | 3 |
| 172.28.1.35 | modality | 223 | 0.4574 | 0 | 0 |
| 172.28.1.51 | workstation | 715 | 0.5259 | 25 | 4 |
| 172.28.1.52 | workstation | 574 | 0.1707 | 10 | 4 |
| 172.28.1.60 | monitoring | 705 | 0.0 | 0 | 0 |

11 runs started while their host was still under an earlier action (level_at_start > 0 in runs.csv): their containment time can be shorter than their detection time.

`class_correct` = share of alarmed windows whose predicted attack class equals the true class (novel variants are judged against their parent class).
