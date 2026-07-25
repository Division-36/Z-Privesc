# Authors

## Project lead

- **Zierax (Ziad Salah)** <zs.01117875692@gmail.com> - design, all
  eight probes, Truthimatics integration, risk aggregator, audit
  emitter, test framework, documentation, CI, release engineering.

## Acknowledgements

- The Truthimatics design is reused from the [Z-Jail](https://github.com/Division-36/Z-Jail) project, also
  authored by Zierax.
- Build and packaging conventions borrow heavily from
  [csmith-project/csmith](https://github.com/csmith-project/csmith)
  and the [Linux kernel kbuild](https://www.kernel.org/doc/Documentation/kbuild/)
  systems.
- This tool owes a debt to the publicly published GTFOBins catalog and
  the [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) project, both
  of which inform the dangerous-basename classification in
  `src/probes/suid.c`.

## License

Z-Privesc is released under the [MIT License](LICENSE).
Contributions are accepted under the same license.
