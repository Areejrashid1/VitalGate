# VitalGate test-bed evaluation

Frozen bundle 2026-11-16 17:37:16 | 59 pcaps | 4,795 windows | 8.3 host-hours | 17 attack runs (0 not seen by the sensor)
## Detection and response
| policy | contained | runs | median_TTC_s | benign_min_restricted_per_h | clinical_min_blocked_per_h | false_actions_per_h |
|---|---|---|---|---|---|---|
| ladder | 16 | 17 | 3.5 | 1.5809 | 0.0 | 1.4409 |
| binary | 16 | 17 | 3.5 | 1.1087 | 0.1801 | 2.8817 |

Detected 16/17 runs, median time to detect 3.45 s (from the attack's real start), false alarm episodes 2.8817 per host-hour.

## Known vs novel techniques
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| known | 7 | 7 | [59, 100] | 7 | 3.4 | 3.4 | 0.813 |
| novel | 10 | 9 | [55, 100] | 9 | 3.7 | 3.7 | 0.73 |

## By class
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce | 2 | 2 | [16, 100] | 2 | 2.75 | 2.75 | 1.0 |
| assoc_flood | 2 | 2 | [16, 100] | 2 | 116.85000000000001 | 116.85000000000001 | 0.375 |
| exfiltration | 3 | 3 | [29, 100] | 3 | 10.3 | 10.3 | 0.927 |
| malformed_pdu | 2 | 1 | [1, 99] | 1 | 3.5 | 3.5 | 0.333 |
| preamble_polyglot | 3 | 3 | [29, 100] | 3 | 1.7 | 1.7 | 0.993 |
| ransomware_like | 2 | 2 | [16, 100] | 2 | 3.55 | 3.55 | 0.752 |
| recon | 3 | 3 | [29, 100] | 3 | 4.6 | 4.6 | 0.638 |

## By variant
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| ae_bruteforce/echo_guess | 1 | 1 | [2, 100] | 1 | 3.3 | 3.3 | 1.0 |
| ae_bruteforce/find_guess (novel) | 1 | 1 | [2, 100] | 1 | 2.2 | 2.2 | 1.0 |
| assoc_flood/echo_storm (novel) | 1 | 1 | [2, 100] | 1 | 93.9 | 93.9 | 0.0 |
| assoc_flood/hold_full_rq | 1 | 1 | [2, 100] | 1 | 139.8 | 139.8 | 0.75 |
| exfiltration/drip (novel) | 1 | 1 | [2, 100] | 1 | 49.9 | 49.9 | 1.0 |
| exfiltration/find_get | 1 | 1 | [2, 100] | 1 | 2.9 | 2.9 | 0.944 |
| exfiltration/move_to_self (novel) | 1 | 1 | [2, 100] | 1 | 10.3 | 10.3 | 0.836 |
| malformed_pdu/assoc_fuzz | 1 | 1 | [2, 100] | 1 | 3.5 | 3.5 | 0.333 |
| malformed_pdu/pdata_fuzz (novel) | 1 | 0 | [0, 98] | 0 |  |  |  |
| preamble_polyglot/rest_elf (novel) | 1 | 1 | [2, 100] | 1 | 0.1 | 0.1 | 1.0 |
| preamble_polyglot/rest_mz | 1 | 1 | [2, 100] | 1 | 1.8 | 1.8 | 0.98 |
| preamble_polyglot/stow_mz (novel) | 1 | 1 | [2, 100] | 1 | 1.7 | 1.7 | 1.0 |
| ransomware_like/get_restore | 1 | 1 | [2, 100] | 1 | 3.4 | 3.4 | 0.771 |
| ransomware_like/get_restore_delete (novel) | 1 | 1 | [2, 100] | 1 | 3.7 | 3.7 | 0.732 |
| recon/dicom_ping (novel) | 1 | 1 | [2, 100] | 1 | 8.8 | 8.8 | 0.0 |
| recon/nmap_connect | 1 | 1 | [2, 100] | 1 | 4.6 | 4.6 | 0.915 |
| recon/nmap_syn (novel) | 1 | 1 | [2, 100] | 1 | 0.9 | 0.9 | 1.0 |

## By intensity
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| high | 6 | 6 | [54, 100] | 6 | 2.35 | 2.35 | 0.949 |
| low | 5 | 4 | [28, 99] | 4 | 4.15 | 4.15 | 0.912 |
| slow | 6 | 6 | [54, 100] | 6 | 9.55 | 9.55 | 0.486 |

## By attack source
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|
| modality | 4 | 4 | [40, 100] | 4 | 6.7 | 6.7 | 0.729 |
| unknown | 8 | 7 | [47, 100] | 7 | 2.9 | 2.9 | 0.861 |
| workstation | 5 | 5 | [48, 100] | 5 | 10.3 | 10.3 | 0.664 |

## Benign hosts
| host | role | windows | flagged_share | alarm_windows | max_level |
|---|---|---|---|---|---|
| 172.28.1.31 | modality | 158 | 0.057 | 25 | 3 |
| 172.28.1.32 | modality | 103 | 0.068 | 0 | 2 |
| 172.28.1.33 | modality | 117 | 0.094 | 5 | 3 |
| 172.28.1.34 | modality | 109 | 0.0092 | 0 | 2 |
| 172.28.1.35 | modality | 85 | 0.1412 | 10 | 3 |
| 172.28.1.51 | workstation | 281 | 0.6157 | 185 | 4 |
| 172.28.1.52 | workstation | 240 | 0.3292 | 21 | 4 |
| 172.28.1.60 | monitoring | 270 | 0.0 | 0 | 0 |

5 runs started while their host was still under an earlier action (level_at_start > 0 in runs.csv): their containment time can be shorter than their detection time.

`class_correct` = share of alarmed windows whose predicted attack class equals the true class (novel variants are judged against their parent class).
