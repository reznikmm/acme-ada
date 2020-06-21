--  SPDX-FileCopyrightText: 2020 Max Reznik <reznikmm@gmail.com>
--
--  SPDX-License-Identifier: MIT
----------------------------------------------------------------

with League.JSON.Objects;
with League.Strings;
with League.String_Vectors;
with League.Stream_Element_Vectors;
with League.Calendars;

package ACME is

   type Context is tagged limited private;

   procedure Initialize
     (Self             : in out Context'Class;
      Directory_URL    : League.Strings.Universal_String;
      Terms_Of_Service : out League.Strings.Universal_String);

   procedure Create_Account
     (Self          : in out Context'Class;
      Public_Key    : League.JSON.Objects.JSON_Object;
      Private_Key   : League.Stream_Element_Vectors.Stream_Element_Vector;
      Contact       : League.String_Vectors.Universal_String_Vector;
      TOS_Agreed    : Boolean := True;
      Only_Existing : Boolean := False;
      Account_URL   : out League.Strings.Universal_String);

   type Optional_Date_Time (Is_Set : Boolean := False) is record
      case Is_Set is
         when True =>
            Value : League.Calendars.Date_Time;
         when False =>
            null;
      end case;
   end record;

   procedure Create_Order
     (Self        : in out Context'Class;
      Account_URL : League.Strings.Universal_String;
      Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
      DNS_Id_List : League.String_Vectors.Universal_String_Vector;
      Not_Before  : Optional_Date_Time := (Is_Set => False);
      Not_After   : Optional_Date_Time := (Is_Set => False);
      Auth_List   : out League.String_Vectors.Universal_String_Vector;
      Finalize    : out League.Strings.Universal_String;
      Order_URL   : out League.Strings.Universal_String);

   procedure Get_Order_Status
     (Self        : in out Context'Class;
      Account_URL : League.Strings.Universal_String;
      Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
      Order_URL   : League.Strings.Universal_String;
      Certificate : out League.Strings.Universal_String;
      Status      : out League.Strings.Universal_String);

   type Challenge is record
      URL   : League.Strings.Universal_String;
      Token : League.Strings.Universal_String;
   end record;

   procedure Get_Challenges
     (Self        : in out Context'Class;
      Account_URL : League.Strings.Universal_String;
      Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
      Auth_URL    : League.Strings.Universal_String;
      HTTP        : out Challenge;
      DNS         : out Challenge);

   function Key_Authorization
     (Token      : League.Strings.Universal_String;
      Public_Key : League.JSON.Objects.JSON_Object)
        return League.Strings.Universal_String;

   procedure Challenge_Status
     (Self        : in out Context'Class;
      Account_URL : League.Strings.Universal_String;
      Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
      Challenge   : ACME.Challenge;
      Status      : out League.Strings.Universal_String);

   procedure Challenge_Complete
     (Self        : in out Context'Class;
      Account_URL : League.Strings.Universal_String;
      Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
      Challenge   : ACME.Challenge);

   procedure Finalize_Order
     (Self        : in out Context'Class;
      Account_URL : League.Strings.Universal_String;
      Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
      Finalize    : League.Strings.Universal_String;
      CSR         : League.Stream_Element_Vectors.Stream_Element_Vector);

   procedure Get_Certificate
     (Self        : in out Context'Class;
      Account_URL : League.Strings.Universal_String;
      Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
      Certificate : League.Strings.Universal_String;
      Text        : out League.Strings.Universal_String);

private
   type Context is tagged limited record
      Directory : League.JSON.Objects.JSON_Object;
      Nonce     : League.Strings.Universal_String;
   end record;
end ACME;
