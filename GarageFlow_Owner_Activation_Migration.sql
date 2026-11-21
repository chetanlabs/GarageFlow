-- =============================================================================
-- GarageFlow — Additive Garage Owner Activation & Role Verification Migration
-- =============================================================================
-- Safe, non-destructive, idempotent migration.
-- Works immediately alongside GarageFlow_Superadmin_Migration.sql (even before
-- the 12-table Phase 1-5 schema is executed).
--
-- Run this in: Supabase Dashboard -> SQL Editor -> New query -> Run
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. RPC: complete_garage_owner_setup()
--    Called by a newly invited Garage Owner right after clicking their email
--    confirmation link and setting their password via supabase.auth.updateUser().
--    - Verifies authenticated user has a confirmed email in auth.users.
--    - Matches public.garage_owner_accounts by email without overwriting
--      another user's existing auth_user_id.
--    - Flips status from 'Setup Pending' -> 'Active' and records activated_at.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.complete_garage_owner_setup()
RETURNS TABLE (
  id UUID,
  owner_name TEXT,
  garage_name TEXT,
  owner_email TEXT,
  status TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  v_uid UUID := auth.uid();
  v_email TEXT;
  v_confirmed TIMESTAMPTZ;
  v_owner public.garage_owner_accounts%ROWTYPE;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'Authentication required to complete owner account setup.'
      USING ERRCODE = '42501';
  END IF;

  SELECT lower(u.email), u.email_confirmed_at
    INTO v_email, v_confirmed
    FROM auth.users u
   WHERE u.id = v_uid
   LIMIT 1;

  IF v_email IS NULL THEN
    RAISE EXCEPTION 'Authenticated user record not found.'
      USING ERRCODE = '42501';
  END IF;

  IF v_confirmed IS NULL THEN
    RAISE EXCEPTION 'Email address must be confirmed before activating your owner account.'
      USING ERRCODE = '42501';
  END IF;

  SELECT *
    INTO v_owner
    FROM public.garage_owner_accounts goa
   WHERE lower(goa.owner_email) = v_email
   LIMIT 1;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'No pending Garage Owner invitation was found for %.', v_email
      USING ERRCODE = '42501';
  END IF;

  IF v_owner.status = 'Suspended' THEN
    RAISE EXCEPTION 'This Garage Owner account is Suspended. Contact Superadmin.'
      USING ERRCODE = '42501';
  END IF;

  IF v_owner.auth_user_id IS NOT NULL AND v_owner.auth_user_id <> v_uid THEN
    RAISE EXCEPTION 'This Garage Owner account is already linked to another user.'
      USING ERRCODE = '42501';
  END IF;

  UPDATE public.garage_owner_accounts goa
     SET auth_user_id = v_uid,
         status = 'Active',
         activated_at = COALESCE(goa.activated_at, now()),
         updated_at = now()
   WHERE goa.id = v_owner.id
   RETURNING * INTO v_owner;

  RETURN QUERY
  SELECT v_owner.id, v_owner.owner_name, v_owner.garage_name, v_owner.owner_email, v_owner.status;
END;
$$;

REVOKE ALL ON FUNCTION public.complete_garage_owner_setup() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.complete_garage_owner_setup() TO authenticated;

-- -----------------------------------------------------------------------------
-- 2. RPC: verify_garage_owner_role()
--    Called during ADMIN login to verify the authenticated Supabase user is an
--    Active Garage Owner in public.garage_owner_accounts.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.verify_garage_owner_role()
RETURNS TABLE (
  is_owner BOOLEAN,
  owner_id UUID,
  owner_name TEXT,
  garage_name TEXT,
  owner_email TEXT,
  status TEXT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  v_uid UUID := auth.uid();
  v_email TEXT;
  v_owner public.garage_owner_accounts%ROWTYPE;
BEGIN
  IF v_uid IS NULL THEN
    RETURN QUERY SELECT false, NULL::UUID, NULL::TEXT, NULL::TEXT, NULL::TEXT, NULL::TEXT;
    RETURN;
  END IF;

  SELECT lower(u.email) INTO v_email FROM auth.users u WHERE u.id = v_uid LIMIT 1;

  SELECT *
    INTO v_owner
    FROM public.garage_owner_accounts goa
   WHERE goa.auth_user_id = v_uid
      OR (goa.auth_user_id IS NULL AND lower(goa.owner_email) = v_email)
   LIMIT 1;

  IF FOUND THEN
    RETURN QUERY
    SELECT (v_owner.status = 'Active'), v_owner.id, v_owner.owner_name, v_owner.garage_name, v_owner.owner_email, v_owner.status;
  ELSE
    RETURN QUERY SELECT false, NULL::UUID, NULL::TEXT, NULL::TEXT, NULL::TEXT, NULL::TEXT;
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.verify_garage_owner_role() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.verify_garage_owner_role() TO authenticated;

COMMIT;
