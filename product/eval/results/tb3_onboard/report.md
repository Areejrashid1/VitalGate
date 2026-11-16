# VitalGate test-bed evaluation

Frozen bundle 2026-11-14 19:20:18 | 59 pcaps | 4,795 windows | 8.3 host-hours | 17 attack runs (0 not seen by the sensor)
## Detection and response
| policy | contained | runs | median_TTC_s | benign_min_restricted_per_h | clinical_min_blocked_per_h | false_actions_per_h |
|---|---|---|---|---|---|---|
| ladder | 11 | 17 | 3.4 | 0.1441 | 0.0 | 0.1201 |
| binary | 11 | 17 | 3.4 | 0.1121 | 0.1121 | 0.1201 |

Detected 11/17 runs, median time to detect 3.4 s (from the attack's real start), false alarm episodes 0.1201 per host-hour.

## Known vs novel techniques
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| known | 7 | 6 | [42, 100] | 6 | 3.45 | 3.45 | 0.833 |
| novel | 10 | 5 | [19, 81] | 5 | 2.2 | 2.2 | 0.8 |

## By class
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce | 2 | 2 | [16, 100] | 2 | 2.75 | 2.75 | 1.0 |
| assoc_flood | 2 | 0 | [0, 84] | 0 |  |  |  |
| exfiltration | 3 | 2 | [9, 99] | 2 | 4.4 | 4.4 | 0.972 |
| malformed_pdu | 2 | 1 | [1, 99] | 1 | 3.5 | 3.5 | 0.333 |
| preamble_polyglot | 3 | 3 | [29, 100] | 3 | 1.7 | 1.7 | 0.993 |
| ransomware_like | 2 | 1 | [1, 99] | 1 | 3.4 | 3.4 | 0.743 |
| recon | 3 | 2 | [9, 99] | 2 | 18.7 | 18.7 | 0.5 |

## By variant
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce/echo_guess | 1 | 1 | [2, 100] | 1 | 3.3 | 3.3 | 1.0 |
| ae_bruteforce/find_guess (novel) | 1 | 1 | [2, 100] | 1 | 2.2 | 2.2 | 1.0 |
| assoc_flood/echo_storm (novel) | 1 | 0 | [0, 98] | 0 |  |  |  |
| assoc_flood/hold_full_rq | 1 | 0 | [0, 98] | 0 |  |  |  |
| exfiltration/drip (novel) | 1 | 1 | [2, 100] | 1 | 3.9 | 3.9 | 1.0 |
| exfiltration/find_get | 1 | 1 | [2, 100] | 1 | 4.9 | 4.9 | 0.943 |
| exfiltration/move_to_self (novel) | 1 | 0 | [0, 98] | 0 |  |  |  |
| malformed_pdu/assoc_fuzz | 1 | 1 | [2, 100] | 1 | 3.5 | 3.5 | 0.333 |
| malformed_pdu/pdata_fuzz (novel) | 1 | 0 | [0, 98] | 0 |  |  |  |
| preamble_polyglot/rest_elf (novel) | 1 | 1 | [2, 100] | 1 | 0.1 | 0.1 | 1.0 |
| preamble_polyglot/rest_mz | 1 | 1 | [2, 100] | 1 | 1.8 | 1.8 | 0.98 |
| preamble_polyglot/stow_mz (novel) | 1 | 1 | [2, 100] | 1 | 1.7 | 1.7 | 1.0 |
| ransomware_like/get_restore | 1 | 1 | [2, 100] | 1 | 3.4 | 3.4 | 0.743 |
| ransomware_like/get_restore_delete (novel) | 1 | 0 | [0, 98] | 0 |  |  |  |
| recon/dicom_ping (novel) | 1 | 1 | [2, 100] | 1 | 24.8 | 24.8 | 0.0 |
| recon/nmap_connect | 1 | 1 | [2, 100] | 1 | 12.6 | 12.6 | 1.0 |
| recon/nmap_syn (novel) | 1 | 0 | [0, 98] | 0 |  |  |  |

## By intensity
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| high | 6 | 5 | [36, 100] | 5 | 3.3 | 3.3 | 0.933 |
| low | 5 | 3 | [15, 95] | 3 | 3.9 | 3.9 | 1.0 |
| slow | 6 | 3 | [12, 88] | 3 | 3.5 | 3.5 | 0.444 |

## By attack source
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| modality | 4 | 4 | [40, 100] | 4 | 8.25 | 8.25 | 0.75 |
| unknown | 8 | 7 | [47, 100] | 7 | 3.3 | 3.3 | 0.857 |
| workstation | 5 | 0 | [0, 52] | 0 |  |  |  |

## Benign hosts
| host | role | windows | flagged_share | alarm_windows | max_level |
|---|---|---|---|---|---|
| 172.28.1.31 | modality | 158 | 0.1709 | 11 | 3 |
| 172.28.1.32 | modality | 103 | 0.068 | 1 | 3 |
| 172.28.1.33 | modality | 117 | 0.2991 | 0 | 0 |
| 172.28.1.34 | modality | 109 | 0.0275 | 0 | 2 |
| 172.28.1.35 | modality | 85 | 0.3529 | 0 | 3 |
| 172.28.1.51 | workstation | 281 | 0.4733 | 0 | 0 |
| 172.28.1.52 | workstation | 240 | 0.1542 | 0 | 0 |
| 172.28.1.60 | monitoring | 270 | 0.0 | 0 | 0 |

3 runs started while their host was still under an earlier action (level_at_start > 0 in runs.csv): their containment time can be shorter than their detection time.

`class_correct` = share of alarmed windows whose predicted attack class equals the true class (novel variants are judged against their parent class).
