# Prostho Scanner MVP

Mobile-first prosthodontic scanner MVP — now with a **real** depth-sensing
scanning pipeline instead of placeholder data.

## What's real here

- **Pose tracking**: comes from the device's own WebXR/ARCore visual-inertial
  odometry (not a hand-rolled SLAM implementation).
- **Depth data**: real per-pixel depth from ARCore via the
  [WebXR Depth Sensing API](https://www.w3.org/TR/webxr-depth-sensing-1/)
  (`XRFrame.getDepthInformation`).
- **3D reconstruction**: each captured frame's depth grid is unprojected into
  actual 3D points using the frame's real projection matrix and camera pose,
  then triangulated into a mesh. Triangles that straddle a depth discontinuity
  (an object edge against the background) are dropped rather than bridged, so
  the mesh doesn't fabricate geometry that was never measured.
- **Exports**: real binary STL (one file, all captured frames' triangles) and
  real ASCII PLY point cloud — both are valid files you can open in
  MeshLab / Blender / CloudCompare, not empty shells.

## Requirements

- **Android phone with ARCore support, using Chrome.** This is the WebXR
  Depth Sensing target this build was made for. iOS Safari does not support
  WebXR depth-sensing at all — on iPhone (or any unsupported browser) the app
  falls back to a plain camera preview with scanning disabled.
- **HTTPS**, even for local testing. Both `getUserMedia` (camera) and WebXR
  require a secure context. `vite dev` is configured with a self-signed cert
  (`@vitejs/plugin-basic-ssl`) — Chrome will warn about it once; accept it on
  your own network.

## Run

```bash
npm install
npm run dev
```

Then open `https://<your-computer's-LAN-IP>:5173` on the Android phone (same
Wi-Fi network), accept the certificate warning, and grant camera/AR
permissions.

## Using it

1. **Start Scan** — requests an AR session. You'll see the real camera
   passthrough with a live green point cloud overlay from the current depth
   frame.
2. **Capture** — locks in a higher-resolution mesh from the current frame
   into the accumulated scan (rendered as an opaque grey surface).
3. Move around and capture from a few angles.
4. **Export STL / Export PLY** — downloads the accumulated real geometry.
5. **Clear** — resets the current scan.

## Known limitations (honest MVP scope)

- **No cross-frame fusion.** Captured frames are placed correctly in world
  space (via the device's tracked pose), but overlapping frames are not
  merged into one watertight mesh — you'll see overlapping surfaces where
  scans overlap. A production version would add ICP registration refinement
  and volumetric fusion (e.g. TSDF) to merge frames into a single clean mesh.
- **ARCore depth accuracy** at close range (intraoral distances, a few cm) is
  workable but noisier than a dedicated structured-light/confocal dental
  scanner — this MVP is meant for full-arch/study-model scale scanning
  distances (10–40 cm), not sub-millimeter clinical impressions.
- **No filtering/smoothing pass** (e.g. bilateral filtering, outlier removal)
  is applied yet — raw depth samples go straight into the mesh.
- **iOS is unsupported** for real scanning, since WebXR depth-sensing isn't
  available in Safari.
