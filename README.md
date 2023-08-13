hiera-eyaml-kms
===============

This is a plugin encryptor for the hiera-eyaml project (hosted https://github.com/TomPoulton/hiera-eyaml/).

*hiera-eyaml-kms encrypts and decrypts Hiera data using AWS KMS.*

AWS KMS is a service that encrypts and decrypts data through API calls. Permissions are controlled by IAM. [Read more about AWS KMS](http://docs.aws.amazon.com/kms/latest/developerguide/overview.html).

Using KMS avoids having to expose private keys to decrypt information when running Puppet.

Requirements
------------

Since this is a plugin for hiera-eyaml, you need to install it first:

```
$ gem install hiera-eyaml
```

You might need to install the aws-sdk for ruby, with the command:

```
$ gem install aws-sdk
```

This plugin uses aws-sdk version 2.

Installation
------------

```
$ gem install hiera-eyaml-kms
```

Then see [hiera-eyaml documentation](https://github.com/TomPoulton/hiera-eyaml) for how to use the eyaml tool to encrypt and use the 'KMS' encryption_type for values to be encrypted with this plugin.

Configuration
-------------

By default this plugin will look for a KMS alias called "helm" if the environment
variable "KMS_ALIAS" is not defined.
