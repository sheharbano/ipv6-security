signature thc-ping-sig {
  ip-proto == icmp
  payload /.*/
  event "THC signature found!"
}
