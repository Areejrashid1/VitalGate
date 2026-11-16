# VitalGate test-bed evaluation

Frozen bundle 2026-11-14 19:20:18 | 13 pcaps | 931 windows | 4.5 host-hours | 0 attack runs (0 not seen by the sensor)
## Detection and response
| policy | contained | runs | median_TTC_s | benign_min_restricted_per_h | clinical_min_blocked_per_h | false_actions_per_h |
|---|---|---|---|---|---|---|
| ladder | 0 | 0 |  | 1.228 | 0.0 | 2.9203 |
| binary | 0 | 0 |  | 1.0109 | 0.4343 | 3.5942 |

Detected 0/0 runs, median time to detect None s (from the attack's real start), false alarm episodes 4.4927 per host-hour.

## Known vs novel techniques
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|

## By class
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|

## By variant
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|

## By intensity
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|

## By attack source
| group | runs | detected | ci95 | contained | median_TTD_s | median_TTC_s | class_correct |
|---|---|---|---|---|---|---|---|

## Benign hosts
| host | role | windows | flagged_share | alarm_windows | max_level |
|---|---|---|---|---|---|
| 172.28.1.31 | modality | 72 | 0.2361 | 3 | 3 |
| 172.28.1.32 | modality | 65 | 0.0615 | 0 | 0 |
| 172.28.1.33 | modality | 79 | 0.4304 | 10 | 3 |
| 172.28.1.34 | modality | 103 | 0.2039 | 18 | 3 |
| 172.28.1.35 | modality | 37 | 0.5676 | 9 | 3 |
| 172.28.1.51 | workstation | 126 | 0.3968 | 36 | 4 |
| 172.28.1.52 | workstation | 271 | 0.2399 | 6 | 4 |
| 172.28.1.60 | monitoring | 178 | 0.0112 | 0 | 0 |

0 runs started while their host was still under an earlier action (level_at_start > 0 in runs.csv): their containment time can be shorter than their detection time.

`class_correct` = share of alarmed windows whose predicted attack class equals the true class (novel variants are judged against their parent class).
