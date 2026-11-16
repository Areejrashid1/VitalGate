# VitalGate test-bed evaluation

Frozen bundle 2026-11-16 17:38:40 | 59 pcaps | 4,795 windows | 8.3 host-hours | 17 attack runs (0 not seen by the sensor)
## Detection and response
| policy | contained | runs | median_TTC_s | benign_min_restricted_per_h | clinical_min_blocked_per_h | false_actions_per_h |
|---|---|---|---|---|---|---|
| ladder | 16 | 17 | 5.2 | 0.3042 | 0.0 | 0.2401 |
| binary | 16 | 17 | 5.2 | 0.1961 | 0.1841 | 0.2401 |

Detected 16/17 runs, median time to detect 5.15 s (from the attack's real start), false alarm episodes 0.2401 per host-hour.

## Known vs novel techniques
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| known | 7 | 7 | [59, 100] | 7 | 3.5 | 3.5 | 0.82 |
| novel | 10 | 9 | [55, 100] | 9 | 6.5 | 6.5 | 0.972 |

## By class
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce | 2 | 2 | [16, 100] | 2 | 2.75 | 2.75 | 1.0 |
| assoc_flood | 2 | 2 | [16, 100] | 2 | 75.85000000000001 | 75.85000000000001 | 0.654 |
| exfiltration | 3 | 2 | [9, 99] | 2 | 26.599999999999998 | 26.599999999999998 | 0.863 |
| malformed_pdu | 2 | 2 | [16, 100] | 2 | 5.0 | 5.0 | 0.881 |
| preamble_polyglot | 3 | 3 | [29, 100] | 3 | 1.7 | 1.7 | 0.993 |
| ransomware_like | 2 | 2 | [16, 100] | 2 | 6.550000000000001 | 6.550000000000001 | 0.857 |
| recon | 3 | 3 | [29, 100] | 3 | 4.9 | 4.9 | 1.0 |

## By variant
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce/echo_guess | 1 | 1 | [2, 100] | 1 | 3.3 | 3.3 | 1.0 |
| ae_bruteforce/find_guess (novel) | 1 | 1 | [2, 100] | 1 | 2.2 | 2.2 | 1.0 |
| assoc_flood/echo_storm (novel) | 1 | 1 | [2, 100] | 1 | 9.9 | 9.9 | 0.933 |
| assoc_flood/hold_full_rq | 1 | 1 | [2, 100] | 1 | 141.8 | 141.8 | 0.375 |
| exfiltration/drip (novel) | 1 | 0 | [0, 98] | 0 |  |  |  |
| exfiltration/find_get | 1 | 1 | [2, 100] | 1 | 8.9 | 8.9 | 0.727 |
| exfiltration/move_to_self (novel) | 1 | 1 | [2, 100] | 1 | 44.3 | 44.3 | 1.0 |
| malformed_pdu/assoc_fuzz | 1 | 1 | [2, 100] | 1 | 3.5 | 3.5 | 0.762 |
| malformed_pdu/pdata_fuzz (novel) | 1 | 1 | [2, 100] | 1 | 6.5 | 6.5 | 1.0 |
| preamble_polyglot/rest_elf (novel) | 1 | 1 | [2, 100] | 1 | 0.1 | 0.1 | 1.0 |
| preamble_polyglot/rest_mz | 1 | 1 | [2, 100] | 1 | 1.8 | 1.8 | 0.98 |
| preamble_polyglot/stow_mz (novel) | 1 | 1 | [2, 100] | 1 | 1.7 | 1.7 | 1.0 |
| ransomware_like/get_restore | 1 | 1 | [2, 100] | 1 | 5.4 | 5.4 | 0.899 |
| ransomware_like/get_restore_delete (novel) | 1 | 1 | [2, 100] | 1 | 7.7 | 7.7 | 0.815 |
| recon/dicom_ping (novel) | 1 | 1 | [2, 100] | 1 | 8.8 | 8.8 | 1.0 |
| recon/nmap_connect | 1 | 1 | [2, 100] | 1 | 2.6 | 2.6 | 1.0 |
| recon/nmap_syn (novel) | 1 | 1 | [2, 100] | 1 | 4.9 | 4.9 | 1.0 |

## By intensity
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| high | 6 | 6 | [54, 100] | 6 | 4.1 | 4.1 | 0.934 |
| low | 5 | 4 | [28, 99] | 4 | 4.55 | 4.55 | 0.954 |
| slow | 6 | 6 | [54, 100] | 6 | 9.350000000000001 | 9.350000000000001 | 0.845 |

## By attack source
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| modality | 4 | 3 | [19, 99] | 3 | 2.6 | 2.6 | 1.0 |
| unknown | 8 | 8 | [63, 100] | 8 | 3.4 | 3.4 | 0.921 |
| workstation | 5 | 5 | [48, 100] | 5 | 9.9 | 9.9 | 0.825 |

## Benign hosts
| host | role | windows | flagged_share | alarm_windows | max_level |
|---|---|---|---|---|---|
| 172.28.1.31 | modality | 158 | 0.0253 | 29 | 3 |
| 172.28.1.32 | modality | 103 | 0.0291 | 0 | 0 |
| 172.28.1.33 | modality | 117 | 0.0342 | 3 | 3 |
| 172.28.1.34 | modality | 109 | 0.0 | 0 | 2 |
| 172.28.1.35 | modality | 85 | 0.0 | 1 | 3 |
| 172.28.1.51 | workstation | 281 | 0.0819 | 2 | 4 |
| 172.28.1.52 | workstation | 240 | 0.1542 | 0 | 3 |
| 172.28.1.60 | monitoring | 270 | 0.0 | 0 | 0 |

3 runs started while their host was still under an earlier action (level_at_start > 0 in runs.csv): their containment time can be shorter than their detection time.

`class_correct` = share of alarmed windows whose predicted attack class equals the true class (novel variants are judged against their parent class).
