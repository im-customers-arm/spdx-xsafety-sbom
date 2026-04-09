Timer Scheduling Requirement
==========================

.. req:: Timer scheduling
   :id: SSR-001
   :type: ssr
   :asil: ASIL_B

   cam-service shall schedule a per-event timer that triggers a safety
   violation if the next event is not received within 1000ms.
