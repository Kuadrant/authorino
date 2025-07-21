# How to release Authorino

## Process

To release a version “vX.Y.Z” of Authorino in GitHub and Quay.io, follow these steps:

1. Pick a `<git-ref>` (SHA-1) as source.

```shell
git checkout <git-ref>
```

2. Create a new tag and named release `vX.Y.Z`. Push the tag to GitHub.

```shell
git tag -a vX.Y.Z -s -m "vX.Y.Z"
git push origin vX.Y.Z
```

Then at the GitHub repository, create a new release from the tag you just pushed. One could start autogenerating the
release notes and then write the change notes highlighting all the new features, bug fixes, enhancements, etc.
([example](https://github.com/Kuadrant/authorino/releases/tag/v0.9.0)).

3. Run the GHA ‘Build and push images’ for the `vX.Y.Z` tag. This will cause a new image to be built and pushed to quay.io/kuadrant/authorino.

## Notes on Authorino’s automated builds

* PRs merged to the main branch of Authorino cause a new image to be built (GH Action) and pushed automatically to
`quay.io/kuadrant/authorino:<git-ref>` – the `quay.io/kuadrant/authorino:latest` tag is also moved to match the latest
`<git-ref>`.
* Authorino repo owns the manifests required by the operand: AuthConfig CRD + role definitions. A copy of these is merged
into a single deployment file in the [Authorino Operator repository](https://github.com/Kuadrant/authorino-operator).
