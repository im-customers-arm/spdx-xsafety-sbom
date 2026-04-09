/**
 * Sample source file with @need markers for testing (Sphinx-Needs format).
 *
 * This mirrors how the real arm-critical-app-monitoring project uses
 * @need[UID] markers alongside (or instead of) @sdoc[UID] markers.
 */

#include "cam_service.h"

// @need[SSR-001]
void schedule_timeout_timer(cam_event_t *event) {
    timer_t timer = create_timer(1000);  /* 1000ms timeout per TSR-001 */
    timer_set_callback(timer, on_timeout_violation);
    timer_start(timer);
    event->timer = timer;
}

// @need[SSR-001, SWA-001]
void cam_receiver_check_timeout(cam_receiver_t *recv) {
    if (recv->last_event_age_ms > 1000) {
        trigger_safe_state();
    }
}
