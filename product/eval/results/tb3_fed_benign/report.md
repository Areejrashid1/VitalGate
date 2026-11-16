# VitalGate test-bed evaluation

Frozen bundle 2026-11-16 17:32:05 | 59 pcaps | 4,795 windows | 8.3 host-hours | 17 attack runs (0 not seen by the sensor)
## Detection and response
| policy | contained | runs | median_TTC_s | benign_min_restricted_per_h | clinical_min_blocked_per_h | false_actions_per_h |
|---|---|---|---|---|---|---|
| ladder | 16 | 17 | 3.4 | 1.3728 | 0.0 | 1.3208 |
| binary | 16 | 17 | 3.4 | 1.0086 | 0.2161 | 2.5215 |

Detected 16/17 runs, median time to detect 3.3499999999999996 s (from the attack's real start), false alarm episodes 3.2419 per host-hour.

## Known vs novel techniques
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| known | 7 | 7 | [59, 100] | 7 | 3.3 | 3.3 | 0.823 |
| novel | 10 | 9 | [55, 100] | 9 | 3.7 | 3.7 | 0.733 |

## By class
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce | 2 | 2 | [16, 100] | 2 | 2.75 | 2.75 | 1.0 |
| assoc_flood | 2 | 2 | [16, 100] | 2 | 116.85000000000001 | 116.85000000000001 | 0.375 |
| exfiltration | 3 | 3 | [29, 100] | 3 | 3.9 | 3.9 | 0.936 |
| malformed_pdu | 2 | 1 | [1, 99] | 1 | 3.5 | 3.5 | 0.333 |
| preamble_polyglot | 3 | 3 | [29, 100] | 3 | 1.7 | 1.7 | 0.993 |
| ransomware_like | 2 | 2 | [16, 100] | 2 | 3.55 | 3.55 | 0.744 |
| recon | 3 | 3 | [29, 100] | 3 | 2.9 | 2.6 | 0.667 |

## By variant
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce/echo_guess | 1 | 1 | [2, 100] | 1 | 3.3 | 3.3 | 1.0 |
| ae_bruteforce/find_guess (novel) | 1 | 1 | [2, 100] | 1 | 2.2 | 2.2 | 1.0 |
| assoc_flood/echo_storm (novel) | 1 | 1 | [2, 100] | 1 | 93.9 | 93.9 | 0.0 |
| assoc_flood/hold_full_rq | 1 | 1 | [2, 100] | 1 | 139.8 | 139.8 | 0.75 |
| exfiltration/drip (novel) | 1 | 1 | [2, 100] | 1 | 3.9 | 3.9 | 1.0 |
| exfiltration/find_get | 1 | 1 | [2, 100] | 1 | 2.9 | 2.9 | 0.944 |
| exfiltration/move_to_self (novel) | 1 | 1 | [2, 100] | 1 | 12.3 | 12.3 | 0.864 |
| malformed_pdu/assoc_fuzz | 1 | 1 | [2, 100] | 1 | 3.5 | 3.5 | 0.333 |
| malformed_pdu/pdata_fuzz (novel) | 1 | 0 | [0, 98] | 0 |  |  |  |
| preamble_polyglot/rest_elf (novel) | 1 | 1 | [2, 100] | 1 | 0.1 | 0.1 | 1.0 |
| preamble_polyglot/rest_mz | 1 | 1 | [2, 100] | 1 | 1.8 | 1.8 | 0.98 |
| preamble_polyglot/stow_mz (novel) | 1 | 1 | [2, 100] | 1 | 1.7 | 1.7 | 1.0 |
| ransomware_like/get_restore | 1 | 1 | [2, 100] | 1 | 3.4 | 3.4 | 0.757 |
| ransomware_like/get_restore_delete (novel) | 1 | 1 | [2, 100] | 1 | 3.7 | 3.7 | 0.732 |
| recon/dicom_ping (novel) | 1 | 1 | [2, 100] | 1 | 8.8 | 8.8 | 0.0 |
| recon/nmap_connect | 1 | 1 | [2, 100] | 1 | 2.6 | 2.6 | 1.0 |
| recon/nmap_syn (novel) | 1 | 1 | [2, 100] | 1 | 2.9 | 0.9 | 1.0 |

## By intensity
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| high | 6 | 6 | [54, 100] | 6 | 2.9 | 2.35 | 0.947 |
| low | 5 | 4 | [28, 99] | 4 | 3.1500000000000004 | 3.1500000000000004 | 0.933 |
| slow | 6 | 6 | [54, 100] | 6 | 10.55 | 10.55 | 0.491 |

## By attack source
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| modality | 4 | 4 | [40, 100] | 4 | 3.25 | 3.25 | 0.75 |
| unknown | 8 | 7 | [47, 100] | 7 | 2.9 | 2.9 | 0.859 |
| workstation | 5 | 5 | [48, 100] | 5 | 12.3 | 12.3 | 0.669 |

## Benign hosts
| host | role | windows | flagged_share | alarm_windows | max_level |
|---|---|---|---|---|---|
| 172.28.1.31 | modality | 158 | 0.1646 | 25 | 3 |
| 172.28.1.32 | modality | 103 | 0.068 | 3 | 3 |
| 172.28.1.33 | modality | 117 | 0.2906 | 6 | 3 |
| 172.28.1.34 | modality | 109 | 0.0275 | 0 | 2 |
| 172.28.1.35 | modality | 85 | 0.2824 | 14 | 3 |
| 172.28.1.51 | workstation | 281 | 0.5125 | 154 | 4 |
| 172.28.1.52 | workstation | 240 | 0.1708 | 12 | 4 |
| 172.28.1.60 | monitoring | 270 | 0.0 | 0 | 0 |

5 runs started while their host was still under an earlier action (level_at_start > 0 in runs.csv): their containment time can be shorter than their detection time.

`class_correct` = share of alarmed windows whose predicted attack class equals the true class (novel variants are judged against their parent class).
