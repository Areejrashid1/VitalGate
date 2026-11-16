# VitalGate test-bed evaluation

Frozen bundle 2026-11-14 19:20:18 | 111 pcaps | 10,062 windows | 41.6 host-hours | 17 attack runs (0 not seen by the sensor)
## Detection and response
| policy | contained | runs | median_TTC_s | benign_min_restricted_per_h | clinical_min_blocked_per_h | false_actions_per_h |
|---|---|---|---|---|---|---|
| ladder | 15 | 17 | 3.1 | 1.3001 | 0.0 | 2.1401 |
| binary | 15 | 17 | 3.1 | 1.0292 | 0.222 | 3.0299 |

Detected 15/17 runs, median time to detect 3.1 s (from the attack's real start), false alarm episodes 3.8715 per host-hour.

## Known vs novel techniques
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| known | 7 | 6 | [42, 100] | 6 | 3.75 | 3.75 | 0.773 |
| novel | 10 | 9 | [55, 100] | 9 | 2.9 | 2.9 | 0.523 |

## By class
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce | 2 | 2 | [16, 100] | 2 | 2.9 | 2.9 | 0.949 |
| assoc_flood | 2 | 1 | [1, 99] | 1 | 0.7 | 0.7 | 0.0 |
| exfiltration | 3 | 2 | [9, 99] | 2 | 24.95 | 24.95 | 0.96 |
| malformed_pdu | 2 | 2 | [16, 100] | 2 | 48.699999999999996 | 48.699999999999996 | 0.059 |
| preamble_polyglot | 3 | 3 | [29, 100] | 3 | 0.4 | 0.4 | 0.675 |
| ransomware_like | 2 | 2 | [16, 100] | 2 | 2.5 | 2.5 | 0.698 |
| recon | 3 | 3 | [29, 100] | 3 | 3.6 | 3.6 | 0.661 |

## By variant
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce/echo_guess | 1 | 1 | [2, 100] | 1 | 4.3 | 4.3 | 1.0 |
| ae_bruteforce/find_guess (novel) | 1 | 1 | [2, 100] | 1 | 1.5 | 1.5 | 0.897 |
| assoc_flood/echo_storm (novel) | 1 | 1 | [2, 100] | 1 | 0.7 | 0.7 | 0.0 |
| assoc_flood/hold_full_rq | 1 | 0 | [0, 98] | 0 |  |  |  |
| exfiltration/drip (novel) | 1 | 0 | [0, 98] | 0 |  |  |  |
| exfiltration/find_get | 1 | 1 | [2, 100] | 1 | 3.8 | 3.8 | 0.944 |
| exfiltration/move_to_self (novel) | 1 | 1 | [2, 100] | 1 | 46.1 | 46.1 | 0.977 |
| malformed_pdu/assoc_fuzz | 1 | 1 | [2, 100] | 1 | 3.8 | 3.8 | 0.119 |
| malformed_pdu/pdata_fuzz (novel) | 1 | 1 | [2, 100] | 1 | 93.6 | 93.6 | 0.0 |
| preamble_polyglot/rest_elf (novel) | 1 | 1 | [2, 100] | 1 | 0.5 | 0.5 | 0.491 |
| preamble_polyglot/rest_mz | 1 | 1 | [2, 100] | 1 | 0.4 | 0.4 | 0.97 |
| preamble_polyglot/stow_mz (novel) | 1 | 1 | [2, 100] | 1 | 0.4 | 0.4 | 0.564 |
| ransomware_like/get_restore | 1 | 1 | [2, 100] | 1 | 2.1 | 2.1 | 0.622 |
| ransomware_like/get_restore_delete (novel) | 1 | 1 | [2, 100] | 1 | 2.9 | 2.9 | 0.774 |
| recon/dicom_ping (novel) | 1 | 1 | [2, 100] | 1 | 3.6 | 3.6 | 0.0 |
| recon/nmap_connect | 1 | 1 | [2, 100] | 1 | 3.7 | 3.7 | 0.983 |
| recon/nmap_syn (novel) | 1 | 1 | [2, 100] | 1 | 3.1 | 3.1 | 1.0 |

## By intensity
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| high | 5 | 5 | [48, 100] | 5 | 3.6 | 3.6 | 0.544 |
| low | 6 | 5 | [36, 100] | 5 | 3.1 | 3.1 | 0.597 |
| slow | 6 | 5 | [36, 100] | 5 | 2.1 | 2.1 | 0.727 |

## By attack source
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| modality | 5 | 3 | [15, 95] | 3 | 3.8 | 3.8 | 0.04 |
| unknown | 6 | 6 | [54, 100] | 6 | 3.0 | 3.0 | 0.882 |
| workstation | 6 | 6 | [54, 100] | 6 | 1.1 | 1.1 | 0.655 |

## Benign hosts
| host | role | windows | flagged_share | alarm_windows | max_level |
|---|---|---|---|---|---|
| 172.28.1.31 | modality | 581 | 0.1429 | 41 | 3 |
| 172.28.1.32 | modality | 365 | 0.0575 | 3 | 2 |
| 172.28.1.33 | modality | 599 | 0.379 | 94 | 3 |
| 172.28.1.34 | modality | 745 | 0.1423 | 39 | 3 |
| 172.28.1.35 | modality | 479 | 0.4342 | 55 | 3 |
| 172.28.1.51 | workstation | 1553 | 0.5048 | 722 | 4 |
| 172.28.1.52 | workstation | 1473 | 0.1752 | 53 | 4 |
| 172.28.1.60 | monitoring | 1492 | 0.0027 | 0 | 0 |

7 runs started while their host was still under an earlier action (level_at_start > 0 in runs.csv): their containment time can be shorter than their detection time.

`class_correct` = share of alarmed windows whose predicted attack class equals the true class (novel variants are judged against their parent class).
