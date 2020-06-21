--  SPDX-FileCopyrightText: 2020 Max Reznik <reznikmm@gmail.com>
--
--  SPDX-License-Identifier: MIT
----------------------------------------------------------------

with Ada.Streams.Stream_IO;
with Ada.Wide_Wide_Text_IO;

with League.Application;
with League.Stream_Element_Vectors;
with League.String_Vectors;
with League.Strings;
with League.JSON.Objects;

with AWS.Client;

with JWS.RS256;

with ACME;

procedure Hello_World_Run is
   function "+" (V : Wide_Wide_String) return League.Strings.Universal_String
     renames League.Strings.To_Universal_String;

   procedure Read_File
     (Name  : String;
      Value : out League.Stream_Element_Vectors.Stream_Element_Vector);

   Domain : constant League.Strings.Universal_String :=
     League.Application.Arguments.Element (1);

   procedure Read_File
     (Name  : String;
      Value : out League.Stream_Element_Vectors.Stream_Element_Vector)
   is
      Input : Ada.Streams.Stream_IO.File_Type;
      Data  : Ada.Streams.Stream_Element_Array (1 .. 4096);
      Last  : Ada.Streams.Stream_Element_Count;
   begin
      Ada.Streams.Stream_IO.Open (Input, Ada.Streams.Stream_IO.In_File, Name);
      Ada.Streams.Stream_IO.Read (Input, Data, Last);
      Ada.Streams.Stream_IO.Close (Input);
      Value.Append (Data (1 .. Last));
   end Read_File;

   Context : ACME.Context;
   Term_Of_Service : League.Strings.Universal_String;
   Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
   Public_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
   CSR : League.Stream_Element_Vectors.Stream_Element_Vector;
   Account : League.Strings.Universal_String;
   Order  : League.Strings.Universal_String;
   Cert  : League.Strings.Universal_String;
   DNS_List : League.String_Vectors.Universal_String_Vector;
   Auth_List : League.String_Vectors.Universal_String_Vector;
   Finalize : League.Strings.Universal_String;
   C1, C2 : ACME.Challenge;
   JWK : League.JSON.Objects.JSON_Object;
   Status : League.Strings.Universal_String;
   Text : League.Strings.Universal_String;
begin
   AWS.Client.Set_Debug (True);

   --  Read keys and CSR
   Read_File ("/tmp/priv.dat", Private_Key);
   Read_File ("/tmp/pub.dat", Public_Key);
   Read_File ("/tmp/csr.dat", CSR);

   Context.Initialize
     (+"https://acme-staging-v02.api.letsencrypt.org/directory",
      Term_Of_Service);

   Ada.Wide_Wide_Text_IO.Put ("Please read Term Of Service: ");
   Ada.Wide_Wide_Text_IO.Put_Line (Term_Of_Service.To_Wide_Wide_String);

   --  Construct JWK from out public key to pass it to CA and create account
   JWK := JWS.RS256.Public_JWK (Public_Key.To_Stream_Element_Array);

   Context.Create_Account
     (Public_Key    => JWK,
      Private_Key   => Private_Key,
      Contact       => League.String_Vectors.Empty_Universal_String_Vector,
      TOS_Agreed    => True,
      Only_Existing => False,
      Account_URL   => Account);

   --  Request domain certificate by creating an order
   DNS_List.Append (Domain);

   Context.Create_Order
     (Account_URL => Account,
      Private_Key => Private_Key,
      DNS_Id_List => DNS_List,
      Auth_List   => Auth_List,
      Finalize    => Finalize,
      Order_URL   => Order);

   --  Get challenges required to fulfill authorization requirements
   Context.Get_Challenges
     (Account_URL => Account,
      Private_Key => Private_Key,
      Auth_URL    => Auth_List (1),
      HTTP        => C1,
      DNS         => C2);

   --  Overcome the HTTP challenge
   Ada.Wide_Wide_Text_IO.Put ("Put this content: ");
   Ada.Wide_Wide_Text_IO.Put_Line
     (ACME.Key_Authorization (C1.Token, JWK).To_Wide_Wide_String);

   Ada.Wide_Wide_Text_IO.Put ("To be accessible at http://");
   Ada.Wide_Wide_Text_IO.Put (Domain.To_Wide_Wide_String);
   Ada.Wide_Wide_Text_IO.Put ("/.well-known/acme-challenge/");
   Ada.Wide_Wide_Text_IO.Put_Line (C1.Token.To_Wide_Wide_String);
   Ada.Wide_Wide_Text_IO.Put_Line ("Then press ENTER");

   declare
      --  Wait ENTER pressing
      Ignore : Wide_Wide_String := Ada.Wide_Wide_Text_IO.Get_Line;
   begin
      null;
   end;

   --  Notify the server
   Context.Challenge_Complete
     (Account_URL => Account,
      Private_Key => Private_Key,
      Challenge   => C1);

   --  Wait the server to verify the challenge
   loop
      Context.Challenge_Status
        (Account_URL => Account,
         Private_Key => Private_Key,
         Challenge   => C1,
         Status      => Status);

      Ada.Wide_Wide_Text_IO.Put ("Challenge Status:");
      Ada.Wide_Wide_Text_IO.Put_Line (Status.To_Wide_Wide_String);

      exit when Status.Ends_With ("valid");  --  valid or invalid
      delay 1.0;
   end loop;

   --  Finalize the order:
   loop
      Context.Get_Order_Status
        (Account_URL => Account,
         Private_Key => Private_Key,
         Order_URL   => Order,
         Certificate => Cert,
         Status      => Status);

      Ada.Wide_Wide_Text_IO.Put ("Order Status:");
      Ada.Wide_Wide_Text_IO.Put_Line (Status.To_Wide_Wide_String);

      exit when Status.Ends_With ("valid");  --  valid or invalid

      if Status.To_Wide_Wide_String = "ready" then
         Context.Finalize_Order
           (Account_URL => Account,
            Private_Key => Private_Key,
            Finalize    => Finalize,
            CSR         => CSR);
      else
         delay 1.0;
      end if;
   end loop;

   --  Download the certificate
   if Status.To_Wide_Wide_String = "valid" then
      Context.Get_Certificate
        (Account_URL => Account,
         Private_Key => Private_Key,
         Certificate => Cert,
         Text        => Text);

      Ada.Wide_Wide_Text_IO.Put_Line (Text.To_Wide_Wide_String);
   end if;
end Hello_World_Run;
