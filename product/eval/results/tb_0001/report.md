# VitalGate test-bed evaluation

Frozen bundle 2026-11-14 19:20:18 | 111 pcaps | 10,021 windows | 42.0 host-hours | 26 attack runs (0 not seen by the sensor)
## Detection and response
| policy | contained | runs | median_TTC_s | benign_min_restricted_per_h | clinical_min_blocked_per_h | false_actions_per_h |
|---|---|---|---|---|---|---|
| ladder | 21 | 26 | 3.5 | 1.2684 | 0.0 | 1.9526 |
| binary | 21 | 26 | 3.5 | 1.0001 | 0.2016 | 2.8813 |

Detected 21/26 runs, median time to detect 3.5 s (from the attack's real start), false alarm episodes 3.7623 per host-hour.

## Known vs novel techniques
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| known | 8 | 7 | [47, 100] | 7 | 3.3 | 3.3 | 0.699 |
| novel | 18 | 14 | [52, 94] | 14 | 3.75 | 3.75 | 0.823 |

## By class
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce | 3 | 3 | [29, 100] | 3 | 3.5 | 3.5 | 1.0 |
| assoc_flood | 3 | 0 | [0, 71] | 0 |  |  |  |
| exfiltration | 5 | 5 | [48, 100] | 5 | 9.6 | 9.6 | 0.93 |
| malformed_pdu | 4 | 2 | [7, 93] | 2 | 3.4 | 3.4 | 0.049 |
| preamble_polyglot | 4 | 4 | [40, 100] | 4 | 0.95 | 0.95 | 1.0 |
| ransomware_like | 2 | 2 | [16, 100] | 2 | 5.9 | 5.9 | 0.766 |
| recon | 5 | 5 | [48, 100] | 5 | 3.3 | 3.3 | 0.625 |

## By variant
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce/echo_guess | 1 | 1 | [2, 100] | 1 | 3.8 | 3.8 | 1.0 |
| ae_bruteforce/find_guess (novel) | 2 | 2 | [16, 100] | 2 | 3.4 | 3.4 | 1.0 |
| assoc_flood/echo_storm (novel) | 2 | 0 | [0, 84] | 0 |  |  |  |
| assoc_flood/hold_full_rq | 1 | 0 | [0, 98] | 0 |  |  |  |
| exfiltration/drip (novel) | 2 | 2 | [16, 100] | 2 | 16.0 | 16.0 | 0.978 |
| exfiltration/find_get | 1 | 1 | [2, 100] | 1 | 0.8 | 0.8 | 1.0 |
| exfiltration/move_to_self (novel) | 2 | 2 | [16, 100] | 2 | 83.55 | 83.55 | 0.849 |
| malformed_pdu/assoc_fuzz | 2 | 2 | [16, 100] | 2 | 3.4 | 3.4 | 0.049 |
| malformed_pdu/pdata_fuzz (novel) | 2 | 0 | [0, 84] | 0 |  |  |  |
| preamble_polyglot/rest_elf (novel) | 1 | 1 | [2, 100] | 1 | 1.0 | 1.0 | 1.0 |
| preamble_polyglot/rest_mz | 1 | 1 | [2, 100] | 1 | 0.9 | 0.9 | 1.0 |
| preamble_polyglot/stow_mz (novel) | 2 | 2 | [16, 100] | 2 | 1.0 | 1.0 | 1.0 |
| ransomware_like/get_restore | 1 | 1 | [2, 100] | 1 | 4.0 | 4.0 | 0.808 |
| ransomware_like/get_restore_delete (novel) | 1 | 1 | [2, 100] | 1 | 7.8 | 7.8 | 0.725 |
| recon/dicom_ping (novel) | 2 | 2 | [16, 100] | 2 | 3.0 | 3.0 | 0.07 |
| recon/nmap_connect | 1 | 1 | [2, 100] | 1 | 3.3 | 3.3 | 0.985 |
| recon/nmap_syn (novel) | 2 | 2 | [16, 100] | 2 | 3.15 | 2.15 | 1.0 |

## By intensity
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| high | 11 | 9 | [48, 98] | 9 | 2.3 | 1.5 | 0.754 |
| low | 8 | 7 | [47, 100] | 7 | 3.8 | 3.8 | 0.829 |
| slow | 7 | 5 | [29, 96] | 5 | 3.3 | 3.3 | 0.764 |

## By attack source
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| modality | 4 | 4 | [40, 100] | 4 | 3.8 | 3.8 | 0.477 |
| unknown | 16 | 11 | [41, 89] | 11 | 3.3 | 3.3 | 0.883 |
| workstation | 6 | 6 | [54, 100] | 6 | 3.55 | 3.15 | 0.799 |

## Benign hosts
| host | role | windows | flagged_share | alarm_windows | max_level |
|---|---|---|---|---|---|
| 172.28.1.31 | modality | 558 | 0.138 | 18 | 3 |
| 172.28.1.32 | modality | 365 | 0.0575 | 3 | 2 |
| 172.28.1.33 | modality | 599 | 0.379 | 94 | 3 |
| 172.28.1.34 | modality | 745 | 0.1423 | 39 | 3 |
| 172.28.1.35 | modality | 476 | 0.4328 | 55 | 3 |
| 172.28.1.51 | workstation | 1552 | 0.5052 | 721 | 4 |
| 172.28.1.52 | workstation | 1462 | 0.1751 | 53 | 4 |
| 172.28.1.60 | monitoring | 1489 | 0.0027 | 0 | 0 |

9 runs started while their host was still under an earlier action (level_at_start > 0 in runs.csv): their containment time can be shorter than their detection time.

`class_correct` = share of alarmed windows whose predicted attack class equals the true class (novel variants are judged against their parent class).
