FROM quay.io/fedora/fedora-minimal@sha256:94938a50b2d2ca73dbaa2529e4f4697e3f734276139ebb5767866b064746532d AS refreshed

# Exclude the optional OpenH264 repository from this image.
RUN rm -f /etc/yum.repos.d/fedora-cisco-openh264.repo \
 && dnf --disable-repo='*' --enable-repo=fedora --enable-repo=updates \
      -y upgrade --refresh --setopt=install_weak_deps=False \
 && dnf clean all \
 && rm -rf /var/cache/dnf

FROM refreshed AS dotnet
RUN dnf --disable-repo='*' --enable-repo=fedora --enable-repo=updates \
      -y install dotnet-sdk-10.0 --setopt=install_weak_deps=False \
 && dnf clean all \
 && rm -rf /var/cache/dnf

FROM dotnet AS hermes-tools
RUN dnf --disable-repo='*' --enable-repo=fedora --enable-repo=updates \
      -y install python3 git-core --setopt=install_weak_deps=False \
 && dnf --disable-repo='*' --enable-repo=fedora --enable-repo=updates \
      -y upgrade --refresh --setopt=install_weak_deps=False \
 && dnf clean all \
 && rm -rf /var/cache/dnf

FROM hermes-tools AS node-tools
RUN dnf --disable-repo='*' --enable-repo=fedora --enable-repo=updates \
      -y install nodejs24 nodejs24-npm --setopt=install_weak_deps=False \
 && dnf --disable-repo='*' --enable-repo=fedora --enable-repo=updates \
      -y upgrade --refresh --setopt=install_weak_deps=False \
 && dnf clean all \
 && rm -rf /var/cache/dnf

FROM node-tools AS python-tools
RUN dnf --disable-repo='*' --enable-repo=fedora --enable-repo=updates \
      -y install python3-uv --setopt=install_weak_deps=False \
 && dnf --disable-repo='*' --enable-repo=fedora --enable-repo=updates \
      -y upgrade --refresh --setopt=install_weak_deps=False \
 && dnf clean all \
 && rm -rf /var/cache/dnf

FROM python-tools AS devtools
RUN dnf --disable-repo='*' --enable-repo=fedora --enable-repo=updates \
      -y install gh azure-cli python3-antlr4-runtime ripgrep --setopt=install_weak_deps=False \
 && dnf --disable-repo='*' --enable-repo=fedora --enable-repo=updates \
      -y upgrade --refresh --setopt=install_weak_deps=False \
 && dnf clean all \
 && rm -rf /var/cache/dnf

FROM devtools AS final
WORKDIR /workspace
COPY rpm-packages.lock /usr/share/hermes-dev/rpm-packages.lock
ARG PACKAGE_LOCK_SHA256
ARG RECIPE_SHA256
RUN test "$(sha256sum /usr/share/hermes-dev/rpm-packages.lock | cut -d' ' -f1)" = "$PACKAGE_LOCK_SHA256" \
 && rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > /tmp/installed-rpms \
 && python3 -c 'import pathlib,sys; expected=pathlib.Path("/usr/share/hermes-dev/rpm-packages.lock").read_text(); actual=pathlib.Path("/tmp/installed-rpms").read_text(); sys.exit(expected != actual)' \
 && rm -f /tmp/installed-rpms
LABEL org.opencontainers.image.base.name="quay.io/fedora/fedora-minimal" \
      org.opencontainers.image.base.digest="sha256:94938a50b2d2ca73dbaa2529e4f4697e3f734276139ebb5767866b064746532d" \
      org.thesereyn.package-lock.sha256="${PACKAGE_LOCK_SHA256}" \
      org.thesereyn.recipe.sha256="${RECIPE_SHA256}"
CMD ["bash"]
