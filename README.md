# A2
This is a small Java program that I wrote with my friend Anthony for our networking class. It is meant to perform similarly to a tool like `dig`. It requests DNS records for a given domain.

## Bugs
There is a note on [line 106]() of `DNSlookup.java`. In situations where a domain would be resolved as a nameserver, we had no effective way to continue lookup. I think this is the only section of the assignment where we lost marks.


