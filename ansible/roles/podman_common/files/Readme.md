podman_common role helper files

Purpose:
- Install and configure podman
- Create named podman volumes
- Optionally pull images used by subsequent roles
- Prepare host directories and SELinux relabeling for bind mounts

Variables of interest (defaults/main.yml):
- podman_volumes: list of { name: <volname>, mount: <containerpath>, hostpath: <hostpath optional>, labels: <labels> }
- podman_pull_images: images to pre-pull

Usage:
Include role early in your playbook and set variables as needed. The role is intentionally minimal and safe for idempotent runs.
